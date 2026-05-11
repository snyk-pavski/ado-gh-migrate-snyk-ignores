"""Capture stage: pull policies + projects + targets + issues for one org.

Read-only. Writes to <state_root>/<group_id>/<org_id>/:
    policies.json          — ignore policies (filtered to scoped project when --project-id is set)
    projects.json          — projects (one when scoped, all SAST projects otherwise)
    targets.json           — targets (one when scoped, all otherwise)
    issues/<project>.json  — issues per project, with signature + key_asset extracted
    capture_summary.json   — counts + timestamps for this run

Idempotent: re-running overwrites the cache.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..config import base_url, default_api_version, resolve_token, state_dir
from ..signature import issue_signature
from ..snyk_client import SnykClient
from ..state import StateStore, now_iso

logger = logging.getLogger(__name__)


def _policy_targets_assets(policy: dict, asset_uuids: set[str]) -> bool:
    """True if any of the policy's conditions references an asset UUID in the given set."""
    conds = (
        ((policy.get("attributes") or {}).get("conditions_group") or {}).get("conditions") or []
    )
    return any(cond.get("value") in asset_uuids for cond in conds)


def capture_org(
    group_id: str,
    org_id: str,
    region: str = "us",
    api_version: str | None = None,
    state_root: Path | None = None,
    project_id: str | None = None,
) -> dict[str, Any]:
    """Capture an org's migration-relevant data.

    If `project_id` is set, scope project + target + issues to that single
    project, AND filter policies down to those whose `conditions_group.conditions[].value`
    matches an asset UUID in the scoped project's issues. The org-wide policy
    count is still recorded in the summary for transparency.
    """
    token = resolve_token(group_id)
    base = base_url(region)
    version = api_version or default_api_version()
    state = StateStore(state_root or state_dir(), group_id, org_id)

    started_at = now_iso()
    summary: dict[str, Any] = {
        "captured_at": started_at,
        "group_id": group_id,
        "org_id": org_id,
        "scoped_project_id": project_id,
        "region": region,
        "api_version": version,
        "policies": 0,
        "policies_org_total": 0,
        "projects": 0,
        "targets": 0,
        "issues_total": 0,
        "issues_per_project": {},
    }

    with SnykClient(base, token, version) as c:
        # 1. Policies — fetch all, defer write until we can filter by scope.
        ignore_policies_all = [
            p
            for p in c.get_paginated(f"/orgs/{org_id}/policies", {"limit": 100})
            if (p.get("attributes") or {}).get("action_type") == "ignore"
        ]
        summary["policies_org_total"] = len(ignore_policies_all)
        logger.info(
            "org %s: %d ignore policies in org (pre-filter)", org_id, len(ignore_policies_all)
        )

        # 2. Projects + targets (scoped or full).
        if project_id:
            project = c.get(f"/orgs/{org_id}/projects/{project_id}").get("data") or {}
            projects = [project] if project else []
            target_ref = (project.get("relationships") or {}).get("target", {}).get("data") or {}
            target_id = target_ref.get("id")
            targets = []
            if target_id:
                tgt = c.get(f"/orgs/{org_id}/targets/{target_id}").get("data")
                if tgt:
                    targets = [tgt]
            logger.info(
                "org %s: scoped to project %s (target=%s)", org_id, project_id, target_id
            )
        else:
            projects = list(
                c.get_paginated(
                    f"/orgs/{org_id}/projects", {"limit": 100, "types": "sast"}
                )
            )
            targets = list(c.get_paginated(f"/orgs/{org_id}/targets", {"limit": 100}))

        state.write(
            "projects.json",
            {"captured_at": started_at, "count": len(projects), "projects": projects},
        )
        summary["projects"] = len(projects)
        logger.info("org %s: captured %d projects", org_id, len(projects))

        state.write(
            "targets.json",
            {"captured_at": started_at, "count": len(targets), "targets": targets},
        )
        summary["targets"] = len(targets)
        logger.info("org %s: captured %d targets", org_id, len(targets))

        # 3. Issues per project — collect asset UUIDs as we go for policy filtering.
        (state.dir / "issues").mkdir(exist_ok=True)
        asset_uuids_in_scope: set[str] = set()
        for proj in projects:
            pid = proj.get("id")
            if not pid:
                continue
            issues = list(
                c.get_paginated(
                    f"/orgs/{org_id}/issues",
                    {
                        "limit": 100,
                        "scan_item.id": pid,
                        "scan_item.type": "project",
                        "type": "code",
                    },
                )
            )
            for i in issues:
                ka = (i.get("attributes") or {}).get("key_asset")
                if ka:
                    asset_uuids_in_scope.add(ka)
            state.write(
                f"issues/{pid}.json",
                {
                    "captured_at": started_at,
                    "project_id": pid,
                    "count": len(issues),
                    "issues": [
                        {
                            "id": i.get("id"),
                            "key_asset": (i.get("attributes") or {}).get("key_asset"),
                            "ignored": (i.get("attributes") or {}).get("ignored"),
                            "signature": list(issue_signature(i)),
                            "_raw": i,
                        }
                        for i in issues
                    ],
                },
            )
            summary["issues_total"] += len(issues)
            summary["issues_per_project"][pid] = len(issues)
            logger.info("project %s: captured %d issues", pid, len(issues))

        # 4. Filter policies to scope (if scoped), then write.
        if project_id:
            scoped_policies = [
                p for p in ignore_policies_all
                if _policy_targets_assets(p, asset_uuids_in_scope)
            ]
            logger.info(
                "scope filter: %d/%d ignore policies apply to scoped project",
                len(scoped_policies),
                len(ignore_policies_all),
            )
        else:
            scoped_policies = ignore_policies_all

        state.write(
            "policies.json",
            {
                "captured_at": started_at,
                "scoped_to_project_id": project_id,
                "org_total_ignore_policies": len(ignore_policies_all),
                "count": len(scoped_policies),
                "policies": scoped_policies,
            },
        )
        summary["policies"] = len(scoped_policies)

    state.write("capture_summary.json", summary)
    return summary
