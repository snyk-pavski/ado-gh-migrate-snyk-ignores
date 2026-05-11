"""Map stage: produce url_mapping.json by walking captured ADO targets and applying the resolver.

Read-only against the network — operates entirely on captured state files.
Source and destination Snyk locations are assumed to be the same org.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..config import state_dir as default_state_dir
from ..mapping import MappingConfig
from ..state import StateStore, now_iso

logger = logging.getLogger(__name__)


def _integration_type(target: dict) -> str | None:
    rels = target.get("relationships") or {}
    integ = (rels.get("integration") or {}).get("data") or {}
    return (integ.get("attributes") or {}).get("integration_type")


def map_org(
    group_id: str,
    org_id: str,
    mapping_path: Path,
    state_root: Path | None = None,
) -> dict[str, Any]:
    """Apply URL resolver to every captured ADO target. Output: url_mapping.json."""
    state_root = state_root or default_state_dir()
    state = StateStore(state_root, group_id, org_id)

    targets_doc = state.read("targets.json")
    if not targets_doc:
        raise RuntimeError(
            f"no targets at {state.dir}/targets.json — run `capture` for "
            f"({group_id}, {org_id}) first"
        )
    raw_targets: list[dict] = targets_doc.get("targets") or []
    config = MappingConfig.load(mapping_path)

    started = now_iso()
    counts = {"override": 0, "derivation": 0, "unmapped": 0, "skipped_non_ado": 0}
    entries: list[dict[str, Any]] = []

    for t in raw_targets:
        integ_type = _integration_type(t)
        if integ_type != "azure-repos":
            counts["skipped_non_ado"] += 1
            continue

        attrs = t.get("attributes") or {}
        url = attrs.get("url")
        target_id = t.get("id")

        resolved = config.resolve(url) if url else {
            "destination_url": None,
            "resolved_via": "unmapped",
        }
        counts[resolved["resolved_via"]] += 1

        entries.append({
            "source_target_id": target_id,
            "source_target_url": url,
            "source_display_name": attrs.get("display_name"),
            "destination_target_url": resolved["destination_url"],
            "resolved_via": resolved["resolved_via"],
            # Filled by the verify stage:
            "destination_target_id": None,
            "destination_project_ids": [],
            "verify_status": "pending",
            "verify_notes": [],
        })

    output = {
        "mapped_at": started,
        "group_id": group_id,
        "org_id": org_id,
        "mapping_file": str(mapping_path),
        "counts": counts,
        "entries": entries,
    }
    state.write("url_mapping.json", output)
    logger.info(
        "map: %d ADO targets — override=%d derivation=%d unmapped=%d (skipped %d non-ADO)",
        sum(counts[k] for k in ("override", "derivation", "unmapped")),
        counts["override"],
        counts["derivation"],
        counts["unmapped"],
        counts["skipped_non_ado"],
    )
    return output
