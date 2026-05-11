"""Verify stage: confirm destination targets exist for each mapped entry.

Reads url_mapping.json (output of `map`) plus the same org's captured
targets/projects. Augments the mapping with `destination_target_id` +
`destination_project_ids` and a `verify_status`. Source and destination
are expected to live in the same Snyk org.

This stage is offline: it does NOT call the Snyk API. The user must have
run `capture` (covering BOTH ADO and GitHub targets in the same org).

Verify statuses:
  verified                  — destination target found and at least one project on it
  verified_no_projects      — destination target found but no projects yet (re-import incomplete?)
  destination_target_missing — proposed destination URL has no matching target in captured state
  unmapped                  — map stage did not resolve a destination URL
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..config import state_dir as default_state_dir
from ..state import StateStore, now_iso

logger = logging.getLogger(__name__)


def verify_org(
    group_id: str,
    org_id: str,
    state_root: Path | None = None,
) -> dict[str, Any]:
    """Annotate url_mapping.json with destination_target_id and verify_status."""
    state_root = state_root or default_state_dir()
    state = StateStore(state_root, group_id, org_id)
    mapping = state.read("url_mapping.json")
    if not mapping:
        raise RuntimeError(f"no url_mapping.json at {state.dir} — run `map` first")

    targets_doc = state.read("targets.json") or {}
    projects_doc = state.read("projects.json") or {}
    targets: list[dict] = targets_doc.get("targets") or []
    projects: list[dict] = projects_doc.get("projects") or []

    url_to_target = {
        (t.get("attributes") or {}).get("url"): t
        for t in targets
        if (t.get("attributes") or {}).get("url")
    }
    target_id_to_projects: dict[str, list[dict]] = {}
    for p in projects:
        tid = (
            ((p.get("relationships") or {}).get("target") or {})
            .get("data", {})
            .get("id")
        )
        if tid:
            target_id_to_projects.setdefault(tid, []).append(p)

    counts: dict[str, int] = {}
    for entry in mapping.get("entries") or []:
        dst_url = entry.get("destination_target_url")
        if entry.get("resolved_via") == "unmapped" or not dst_url:
            entry["verify_status"] = "unmapped"
            entry["verify_notes"] = [
                "no destination URL resolved by map stage; add an explicit override or expand the derivation rule"
            ]
            counts["unmapped"] = counts.get("unmapped", 0) + 1
            continue

        dst_target = url_to_target.get(dst_url)
        if not dst_target:
            entry["verify_status"] = "destination_target_missing"
            entry["verify_notes"] = [
                f"no target with url={dst_url!r} captured in this org — "
                f"either the GitHub re-import has not happened yet, or the URL "
                f"in the mapping is wrong"
            ]
            counts["destination_target_missing"] = (
                counts.get("destination_target_missing", 0) + 1
            )
            continue

        target_id = dst_target.get("id")
        projects_on_target = target_id_to_projects.get(target_id, [])
        entry["destination_target_id"] = target_id
        entry["destination_project_ids"] = [p.get("id") for p in projects_on_target]
        if not projects_on_target:
            entry["verify_status"] = "verified_no_projects"
            entry["verify_notes"] = [
                "target exists but has no projects yet (scan may still be running)"
            ]
            counts["verified_no_projects"] = counts.get("verified_no_projects", 0) + 1
        else:
            entry["verify_status"] = "verified"
            counts["verified"] = counts.get("verified", 0) + 1

    mapping["verified_at"] = now_iso()
    mapping["verify_counts"] = counts
    state.write("verify.json", mapping)
    logger.info("verify: %s", counts)
    return mapping
