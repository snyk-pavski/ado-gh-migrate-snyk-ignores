"""Apply stage: plan + (optionally) execute the policy and project-metadata migration.

`build_plan` is read-only and produces `apply_plan.json`. `execute_plan`
walks the plan and POSTs / PATCHes against Snyk, recording per-action
outcomes in `apply_results.json`.

Reads (offline):
  source:      policies.json, projects.json, issues/<project_id>.json, verify.json
  destination: policies.json, projects.json, issues/<project_id>.json
"""
from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any

import httpx

from ..config import (
    base_url,
    default_api_version,
    resolve_token,
    state_dir as default_state_dir,
)
from ..signature import issue_signature
from ..snyk_client import SnykClient
from ..state import StateStore, now_iso

logger = logging.getLogger(__name__)


MIGRATION_BREADCRUMB_PREFIX = "[migrated from azure:"


def _load_issues(state: StateStore, project_id: str) -> list[dict]:
    doc = state.read(f"issues/{project_id}.json")
    if not doc:
        return []
    return doc.get("issues") or []


def _signature_to_key_asset(issues: list[dict]) -> dict[tuple, str]:
    out: dict[tuple, str] = {}
    for i in issues:
        sig = tuple(i.get("signature") or ())
        ka = i.get("key_asset")
        if not ka or not sig:
            continue
        # Last write wins on collision; capture/match-issues will have flagged ambiguity
        out[sig] = ka
    return out


def _key_asset_to_signature(issues: list[dict]) -> dict[str, tuple]:
    out: dict[str, tuple] = {}
    for i in issues:
        sig = tuple(i.get("signature") or ())
        ka = i.get("key_asset")
        if not ka or not sig:
            continue
        out[ka] = sig
    return out


def _projects_on_target(projects: list[dict], target_id: str) -> list[dict]:
    out = []
    for p in projects:
        tid = (
            ((p.get("relationships") or {}).get("target") or {})
            .get("data", {})
            .get("id")
        )
        if tid == target_id:
            out.append(p)
    return out


def _match_projects_by_branch(
    src_projects: list[dict], dst_projects: list[dict]
) -> list[tuple[dict, dict]]:
    """Pair up source and destination projects sharing the same target_reference (branch)."""
    by_branch_dst = {
        (p.get("attributes") or {}).get("target_reference"): p for p in dst_projects
    }
    pairs: list[tuple[dict, dict]] = []
    for sp in src_projects:
        branch = (sp.get("attributes") or {}).get("target_reference")
        dp = by_branch_dst.get(branch)
        if dp:
            pairs.append((sp, dp))
    return pairs


def _build_breadcrumb(source_target_url: str, source_policy_id: str) -> str:
    return f"{MIGRATION_BREADCRUMB_PREFIX} {source_target_url}; old-policy-id: {source_policy_id}]"


def _propose_policy_body(
    src_policy: dict, new_key_asset: str, breadcrumb: str
) -> dict[str, Any]:
    """Build the JSON:API body for POST /orgs/{org}/policies.

    Note Snyk's POST schema is stricter than the GET shape: nullable fields
    on GET (e.g. `expires`) are non-nullable on POST and must be omitted
    when empty rather than sent as null.
    """
    src_attrs = src_policy.get("attributes") or {}
    src_action = (src_attrs.get("action") or {}).get("data") or {}
    original_reason = (src_action.get("reason") or "").strip()
    new_reason = f"{original_reason}\n\n{breadcrumb}".strip() if original_reason else breadcrumb

    action_data: dict[str, Any] = {
        "ignore_type": src_action.get("ignore_type"),
        "reason": new_reason,
    }
    if src_action.get("expires") is not None:
        action_data["expires"] = src_action.get("expires")

    # The CreatePolicyPayload schema (additionalProperties: false) only allows
    # action, action_type, conditions_group, name, source. `review` is GET-only
    # and rejected on POST; the source policy's review state cannot be carried
    # over via the create endpoint.
    attributes: dict[str, Any] = {
        "action_type": "ignore",
        "action": {"data": action_data},
        "conditions_group": {
            "logical_operator": "and",
            "conditions": [
                {
                    "field": "snyk/asset/finding/v1",
                    "operator": "includes",
                    "value": new_key_asset,
                }
            ],
        },
        "name": src_attrs.get("name") or f"Migrated ignore for {new_key_asset}",
    }

    return {"data": {"type": "policy", "attributes": attributes}}


def _policies_referencing_asset(
    dst_policies: list[dict], new_key_asset: str
) -> list[dict]:
    """All destination policies whose conditions reference this asset UUID."""
    out = []
    for p in dst_policies:
        conds = (
            ((p.get("attributes") or {}).get("conditions_group") or {}).get("conditions") or []
        )
        if any(c.get("value") == new_key_asset for c in conds):
            out.append(p)
    return out


def _is_migrated_from_source(policy: dict, source_policy_id: str) -> bool:
    """True if this destination policy carries our breadcrumb for THIS source policy."""
    attrs = policy.get("attributes") or {}
    reason = ((attrs.get("action") or {}).get("data") or {}).get("reason") or ""
    return (
        MIGRATION_BREADCRUMB_PREFIX in reason
        and f"old-policy-id: {source_policy_id}" in reason
    )


def _dst_issue_ignored_for_asset(
    dst_issues: list[dict], new_key_asset: str
) -> bool | None:
    """The `ignored` flag on the destination issue carrying this asset, or None if not found."""
    for i in dst_issues:
        if i.get("key_asset") == new_key_asset:
            return bool(i.get("ignored"))
    return None


def _decide_policy_action_status(
    dst_issue_ignored: bool | None,
    dst_ka_policies: list[dict],
    src_policy_id: str,
) -> tuple[str, dict | None, list[str]]:
    """Decide what to do about a source policy given destination state.

    Uses the destination issue's effective `ignored` flag as the primary signal
    (it reflects what Snyk is actually applying — accounts for rejected,
    expired, and group-level policies). Org-level policies merely referencing
    the asset are not enough to block creation; if they exist but the issue
    isn't currently ignored, they're dangling.

    Returns (status, our_existing_policy_or_None, notes).
    Statuses: already_migrated | already_ignored_in_destination |
              already_ignored_via_higher_scope_policy | would_create
    """
    ours_already = next(
        (p for p in dst_ka_policies if _is_migrated_from_source(p, src_policy_id)),
        None,
    )
    if ours_already is not None:
        return "already_migrated", ours_already, []
    if dst_issue_ignored is True:
        if dst_ka_policies:
            return "already_ignored_in_destination", None, []
        return "already_ignored_via_higher_scope_policy", None, []
    notes: list[str] = []
    if dst_ka_policies:
        notes.append(
            f"note: destination has {len(dst_ka_policies)} dangling policy/policies "
            f"referencing this asset that are not currently effective (likely "
            f"rejected or expired); proceeding to create."
        )
    return "would_create", None, notes


def _propose_project_patch(src_proj: dict, dst_proj: dict) -> dict[str, Any] | None:
    """Return a JSON:API PATCH body for the destination project, or None if nothing to change."""
    src_attrs = src_proj.get("attributes") or {}
    dst_attrs = dst_proj.get("attributes") or {}

    desired: dict[str, Any] = {}
    for field in ("business_criticality", "environment", "lifecycle"):
        src_val = src_attrs.get(field) or []
        dst_val = dst_attrs.get(field) or []
        if src_val and src_val != dst_val:
            desired[field] = src_val

    src_tags = src_attrs.get("tags") or []
    dst_tags = dst_attrs.get("tags") or []
    if src_tags and src_tags != dst_tags:
        desired["tags"] = src_tags

    if not desired:
        return None
    return {"data": {"id": dst_proj.get("id"), "type": "project", "attributes": desired}}


def build_plan(
    group_id: str,
    org_id: str,
    state_root: Path | None = None,
) -> dict[str, Any]:
    """Read state, produce apply_plan.json (no API calls)."""
    state_root = state_root or default_state_dir()
    state = StateStore(state_root, group_id, org_id)
    verify_doc = state.read("verify.json")
    if not verify_doc:
        raise RuntimeError(f"no verify.json at {state.dir} — run `verify` first")

    projects: list[dict] = (state.read("projects.json") or {}).get("projects") or []
    policies: list[dict] = (state.read("policies.json") or {}).get("policies") or []

    actions: list[dict[str, Any]] = []
    summary = {
        "policies_to_create": 0,
        "policies_already_migrated": 0,
        "policies_already_ignored_in_destination": 0,
        "policies_already_ignored_via_higher_scope": 0,
        "policies_unmappable": 0,
        "projects_to_patch": 0,
        "projects_no_change": 0,
        "entries_skipped_unverified": 0,
    }

    for entry in verify_doc.get("entries") or []:
        if entry.get("verify_status") != "verified":
            summary["entries_skipped_unverified"] += 1
            continue

        src_target_id = entry.get("source_target_id")
        src_target_url = entry.get("source_target_url")
        dst_target_id = entry.get("destination_target_id")

        src_proj_list = _projects_on_target(projects, src_target_id)
        dst_proj_list = _projects_on_target(projects, dst_target_id)

        for src_proj, dst_proj in _match_projects_by_branch(src_proj_list, dst_proj_list):
            src_pid = src_proj.get("id")
            dst_pid = dst_proj.get("id")

            # --- project metadata ---
            patch_body = _propose_project_patch(src_proj, dst_proj)
            if patch_body is not None:
                actions.append({
                    "type": "patch_project_metadata",
                    "destination_project_id": dst_pid,
                    "source_project_id": src_pid,
                    "source_target_url": src_target_url,
                    "proposed_patch": patch_body,
                    "status": "would_patch",
                })
                summary["projects_to_patch"] += 1
            else:
                summary["projects_no_change"] += 1

            # --- policies ---
            src_issues = _load_issues(state, src_pid)
            dst_issues = _load_issues(state, dst_pid)
            src_ka_to_sig = _key_asset_to_signature(src_issues)
            dst_sig_to_ka = _signature_to_key_asset(dst_issues)

            # Filter source policies to those touching this source project's findings
            src_assets_for_proj = set(src_ka_to_sig.keys())
            relevant_policies = [
                p for p in policies
                if any(
                    cond.get("value") in src_assets_for_proj
                    for cond in (((p.get("attributes") or {}).get("conditions_group") or {}).get("conditions") or [])
                )
            ]

            for sp in relevant_policies:
                src_policy_id = sp.get("id")
                src_attrs = sp.get("attributes") or {}
                conds = (src_attrs.get("conditions_group") or {}).get("conditions") or []
                old_ka = next(
                    (c.get("value") for c in conds if c.get("value") in src_assets_for_proj),
                    None,
                )
                if not old_ka:
                    continue
                sig = src_ka_to_sig.get(old_ka)
                new_ka = dst_sig_to_ka.get(sig) if sig else None

                src_action_data = (src_attrs.get("action") or {}).get("data") or {}
                base_action = {
                    "type": "create_policy",
                    "source_policy_id": src_policy_id,
                    "source_target_url": src_target_url,
                    "destination_target_url": entry.get("destination_target_url"),
                    "source_project_id": src_pid,
                    "destination_project_id": dst_pid,
                    "old_key_asset": old_ka,
                    "new_key_asset": new_ka,
                    "signature": list(sig) if sig else None,
                    "source_ignore_type": src_action_data.get("ignore_type"),
                    "source_reason": src_action_data.get("reason"),
                    "source_review": src_attrs.get("review"),
                }

                if not new_ka:
                    actions.append({
                        **base_action,
                        "status": "unmappable",
                        "notes": [
                            "no destination issue with matching signature — code may have been fixed, "
                            "rule may have changed, or the file/lines moved"
                        ],
                    })
                    summary["policies_unmappable"] += 1
                    continue

                dst_ka_policies = _policies_referencing_asset(policies, new_ka)
                dst_ignored = _dst_issue_ignored_for_asset(dst_issues, new_ka)
                status, ours_already, notes = _decide_policy_action_status(
                    dst_ignored, dst_ka_policies, src_policy_id
                )

                if status == "already_migrated":
                    actions.append({
                        **base_action,
                        "status": status,
                        "existing_destination_policy_id": ours_already.get("id") if ours_already else None,
                        "notes": ["destination already has a migrated policy with our breadcrumb for this source policy"],
                    })
                    summary["policies_already_migrated"] += 1
                    continue

                if status == "already_ignored_in_destination":
                    actions.append({
                        **base_action,
                        "status": status,
                        "existing_destination_policy_ids": [p.get("id") for p in dst_ka_policies],
                        "existing_destination_policy_reasons": [
                            ((p.get("attributes") or {}).get("action", {}).get("data", {}) or {}).get("reason")
                            for p in dst_ka_policies
                        ],
                        "notes": [
                            "destination issue is currently ignored by an existing org-level policy "
                            "(manual UI ignore or another source policy migrated here). Skipping to "
                            "avoid duplicate; review listed policy id(s) and delete one if you want "
                            "this migrated policy to apply instead."
                        ],
                    })
                    summary["policies_already_ignored_in_destination"] += 1
                    continue

                if status == "already_ignored_via_higher_scope_policy":
                    actions.append({
                        **base_action,
                        "status": status,
                        "notes": [
                            "destination issue is already ignored but no org-level policy references it "
                            "in this org — the ignore most likely comes from a group-level Snyk Code "
                            "Security Policy. Skipping; remove the group rule first if you want this "
                            "migrated policy to take effect at the org level."
                        ],
                    })
                    summary["policies_already_ignored_via_higher_scope"] += 1
                    continue

                # status == "would_create"
                breadcrumb = _build_breadcrumb(src_target_url, src_policy_id)
                actions.append({
                    **base_action,
                    "status": status,
                    "proposed_body": _propose_policy_body(sp, new_ka, breadcrumb),
                    "notes": notes,
                })
                summary["policies_to_create"] += 1

    plan = {
        "planned_at": now_iso(),
        "group_id": group_id,
        "org_id": org_id,
        "summary": summary,
        "actions": actions,
    }
    state.write("apply_plan.json", plan)
    _write_plan_csv(plan, state.dir / "apply_plan.csv")
    logger.info("plan: %s", summary)
    return plan


_PLAN_CSV_FIELDS = [
    "type",
    "status",
    "title",
    "file",
    "lines",
    "source_ignore_type",
    "source_review",
    "source_reason",
    "source_target_url",
    "destination_target_url",
    "source_project_id",
    "destination_project_id",
    "source_policy_id",
    "old_key_asset",
    "new_key_asset",
    "notes",
]

_STATUS_PRIORITY: dict[str, int] = {
    "would_create": 0,
    "would_patch": 1,
    "already_migrated": 2,
    "already_ignored_in_destination": 3,
    "already_ignored_via_higher_scope_policy": 4,
    "unmappable": 5,
    "no_change": 6,
}


def _write_plan_csv(plan: dict[str, Any], path: Path) -> Path:
    """Flat CSV view of apply_plan.json for human review.

    Sorted by status priority so reviewers see actionable rows (would_create /
    would_patch) at the top. Long `reason` strings are truncated for scannability.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    actions = plan.get("actions") or []
    actions_sorted = sorted(
        actions,
        key=lambda a: (_STATUS_PRIORITY.get(a.get("status") or "", 99), a.get("status") or ""),
    )
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_PLAN_CSV_FIELDS)
        w.writeheader()
        for a in actions_sorted:
            sig = a.get("signature") or []
            row: dict[str, Any] = {
                "type": a.get("type"),
                "status": a.get("status"),
                "title": sig[0] if len(sig) > 0 else None,
                "file": sig[1] if len(sig) > 1 else None,
                "lines": (
                    f"{sig[2]}-{sig[4]}"
                    if len(sig) > 4 and sig[2] is not None and sig[4] is not None
                    else None
                ),
                "source_ignore_type": a.get("source_ignore_type"),
                "source_review": a.get("source_review"),
                "source_reason": _truncate(a.get("source_reason"), 200),
                "source_target_url": a.get("source_target_url"),
                "destination_target_url": a.get("destination_target_url"),
                "source_project_id": a.get("source_project_id"),
                "destination_project_id": a.get("destination_project_id"),
                "source_policy_id": a.get("source_policy_id"),
                "old_key_asset": a.get("old_key_asset"),
                "new_key_asset": a.get("new_key_asset"),
                "notes": " | ".join(a.get("notes") or []),
            }
            w.writerow(row)
    return path


def _truncate(s: str | None, n: int) -> str | None:
    if s is None:
        return None
    return s if len(s) <= n else s[: n - 1] + "…"


def execute_plan(
    plan: dict[str, Any],
    group_id: str,
    org_id: str,
    region: str = "us",
    api_version: str | None = None,
    state_root: Path | None = None,
) -> dict[str, Any]:
    """Live executor: walk the plan and POST/PATCH each `would_*` action.

    Per-action try/except so one failure doesn't abort the run. Outcome of
    every action is recorded in apply_results.json under `actions[]` with
    `execution_status` of created / patched / skipped / failed.
    """
    state_root = state_root or default_state_dir()
    state = StateStore(state_root, group_id, org_id)
    token = resolve_token(group_id)
    base = base_url(region)
    version = api_version or default_api_version()

    results: dict[str, Any] = {
        "executed_at": now_iso(),
        "group_id": group_id,
        "org_id": org_id,
        "region": region,
        "api_version": version,
        "summary": {
            "created": 0,
            "patched": 0,
            "already_exists": 0,
            "skipped": 0,
            "failed": 0,
        },
        "actions": [],
    }

    with SnykClient(base, token, version) as c:
        for action in plan.get("actions") or []:
            outcome: dict[str, Any] = dict(action)
            status = action.get("status")
            atype = action.get("type")

            if status not in ("would_create", "would_patch"):
                outcome["execution_status"] = "skipped"
                outcome["execution_reason"] = f"plan status was {status!r}"
                results["summary"]["skipped"] += 1
                results["actions"].append(outcome)
                continue

            try:
                if atype == "create_policy":
                    body = action.get("proposed_body") or {}
                    resp = c.post(f"/orgs/{org_id}/policies", body)
                    outcome["execution_status"] = "created"
                    outcome["created_policy_id"] = (resp.get("data") or {}).get("id")
                    results["summary"]["created"] += 1
                    logger.info(
                        "created policy %s for asset %s (was %s)",
                        outcome.get("created_policy_id"),
                        action.get("new_key_asset"),
                        action.get("old_key_asset"),
                    )
                elif atype == "patch_project_metadata":
                    pid = action.get("destination_project_id")
                    body = action.get("proposed_patch") or {}
                    c.patch(f"/orgs/{org_id}/projects/{pid}", body)
                    outcome["execution_status"] = "patched"
                    results["summary"]["patched"] += 1
                    logger.info("patched project %s metadata", pid)
                else:
                    outcome["execution_status"] = "skipped"
                    outcome["execution_reason"] = f"unknown action type {atype!r}"
                    results["summary"]["skipped"] += 1
            except httpx.HTTPStatusError as e:
                # 409 on create_policy = Snyk already has a matching policy. That's the
                # idempotent goal; treat as soft success. Local state is just stale.
                if atype == "create_policy" and e.response.status_code == 409:
                    outcome["execution_status"] = "already_exists"
                    try:
                        outcome["error_response"] = e.response.json()
                    except Exception:
                        outcome["error_response"] = e.response.text
                    outcome["notes"] = [
                        "Snyk reports a matching policy already exists. Local captured state is "
                        "stale; re-run `ado-gh-migration capture` to refresh and the next plan "
                        "will recognise this via the breadcrumb."
                    ]
                    results["summary"]["already_exists"] += 1
                    logger.info(
                        "policy already exists at Snyk for asset %s (stale local state)",
                        action.get("new_key_asset"),
                    )
                else:
                    outcome["execution_status"] = "failed"
                    outcome["error"] = str(e)
                    try:
                        outcome["error_response"] = e.response.json()
                    except Exception:
                        outcome["error_response"] = e.response.text
                    results["summary"]["failed"] += 1
                    logger.exception(
                        "failed to execute action: %s",
                        action.get("source_policy_id") or action.get("destination_project_id"),
                    )
            except Exception as e:
                outcome["execution_status"] = "failed"
                outcome["error"] = str(e)
                results["summary"]["failed"] += 1
                logger.exception(
                    "failed to execute action: %s",
                    action.get("source_policy_id") or action.get("destination_project_id"),
                )

            results["actions"].append(outcome)

    state.write("apply_results.json", results)
    logger.info("execute: %s", results["summary"])
    return results


def apply_org(
    group_id: str,
    org_id: str,
    region: str = "us",
    api_version: str | None = None,
    state_root: Path | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Convenience wrapper: build_plan, then optionally execute_plan."""
    plan = build_plan(group_id, org_id, state_root)
    if dry_run:
        return {"plan": plan, "dry_run": True}
    results = execute_plan(plan, group_id, org_id, region, api_version, state_root)
    return {"plan": plan, "results": results, "dry_run": False}
