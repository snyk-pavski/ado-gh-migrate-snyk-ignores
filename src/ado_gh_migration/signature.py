"""Stable cross-import signature for Snyk Code findings.

Columns are part of the signature to disambiguate multiple findings of the
same rule on the same line (e.g. several hardcoded passwords on one line of
a test file).
"""
from __future__ import annotations

from typing import Any

Signature = tuple[Any, Any, Any, Any, Any, Any]


def issue_signature(issue: dict) -> Signature:
    """Return (title, file, start_line, start_column, end_line, end_column)."""
    a = issue.get("attributes") or {}
    coords = a.get("coordinates") or []
    first = coords[0] if coords else {}
    reps = first.get("representations") or []
    rep = reps[0] if reps else {}
    src = rep.get("sourceLocation") or {}
    region = src.get("region") or {}
    start = region.get("start") or {}
    end = region.get("end") or {}
    return (
        a.get("title"),
        src.get("file"),
        start.get("line"),
        start.get("column"),
        end.get("line"),
        end.get("column"),
    )
