"""Report stage: human-readable summary of capture + map + verify + apply.

Reads whatever state is present (offline) and emits a concise summary to
stdout. The full structured data lives in the JSON state files; this stage
is just the operator-friendly view.
"""
from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any

from ..config import state_dir as default_state_dir
from ..state import StateStore

logger = logging.getLogger(__name__)


def _heading(s: str) -> str:
    return f"\n=== {s} ===\n"


def report_org(
    group_id: str,
    org_id: str,
    state_root: Path | None = None,
) -> str:
    state_root = state_root or default_state_dir()
    state = StateStore(state_root, group_id, org_id)
    out: list[str] = []

    out.append(f"State directory: {state.dir}")

    cap = state.read("capture_summary.json")
    if cap:
        out.append(_heading("CAPTURE"))
        out.append(f"  captured_at:   {cap.get('captured_at')}")
        out.append(f"  scoped:        {cap.get('scoped_project_id') or '<full org>'}")
        out.append(f"  policies:      {cap.get('policies')}  (org total: {cap.get('policies_org_total')})")
        out.append(f"  projects:      {cap.get('projects')}")
        out.append(f"  targets:       {cap.get('targets')}")
        out.append(f"  issues_total:  {cap.get('issues_total')}")
    else:
        out.append("(no capture_summary.json — has `capture` been run?)")

    url_map = state.read("url_mapping.json")
    if url_map:
        out.append(_heading("MAP (url_mapping.json)"))
        out.append(f"  mapping_file:  {url_map.get('mapping_file')}")
        for k, v in (url_map.get("counts") or {}).items():
            out.append(f"    {k:24s} {v}")

    verify = state.read("verify.json")
    if verify:
        out.append(_heading("VERIFY (verify.json)"))
        for k, v in (verify.get("verify_counts") or {}).items():
            out.append(f"    {k:30s} {v}")

        # Show problematic entries explicitly
        bad: list[dict[str, Any]] = [
            e for e in (verify.get("entries") or [])
            if e.get("verify_status") not in ("verified",)
        ]
        if bad:
            out.append("\n  Entries needing attention:")
            for e in bad[:25]:
                out.append(
                    f"    [{e.get('verify_status')}] {e.get('source_target_url')} "
                    f"→ {e.get('destination_target_url') or '<unmapped>'}"
                )
            if len(bad) > 25:
                out.append(f"    … and {len(bad) - 25} more")

    plan = state.read("apply_plan.json")
    if plan:
        out.append(_heading("APPLY PLAN (apply_plan.json)"))
        out.append(f"  dry_run:       {plan.get('dry_run')}")
        for k, v in (plan.get("summary") or {}).items():
            out.append(f"    {k:30s} {v}")

        # Group actions by status for the operator
        by_status: Counter[str] = Counter(
            (a.get("type"), a.get("status")) for a in (plan.get("actions") or [])
        )
        if by_status:
            out.append("\n  Actions by (type, status):")
            for (typ, status), n in sorted(by_status.items()):
                out.append(f"    {typ:24s} {status:24s} {n}")

    return "\n".join(out)
