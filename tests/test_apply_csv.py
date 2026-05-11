"""Unit tests for apply._write_plan_csv — the human-review CSV view of the plan."""
from __future__ import annotations

import csv
from pathlib import Path

from ado_gh_migration.stages.apply import _write_plan_csv


def _action(**kw) -> dict:
    base = {
        "type": "create_policy",
        "status": "would_create",
        "signature": ["NoSQL Injection", "routes/index.js", 39, 10, 39, 14],
        "source_ignore_type": "wont-fix",
        "source_review": "approved",
        "source_reason": "False positive in test fixture",
        "source_target_url": "https://dev.azure.com/a/b/_git/foo",
        "destination_target_url": "https://github.com/x/foo",
        "source_project_id": "src-proj",
        "destination_project_id": "dst-proj",
        "source_policy_id": "src-pol",
        "old_key_asset": "AAA",
        "new_key_asset": "BBB",
        "notes": [],
    }
    base.update(kw)
    return base


def _read_csv(path: Path) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def test_csv_writes_header_and_rows(tmp_path: Path):
    plan = {"actions": [_action()]}
    p = _write_plan_csv(plan, tmp_path / "apply_plan.csv")
    rows = _read_csv(p)
    assert len(rows) == 1
    assert rows[0]["status"] == "would_create"
    assert rows[0]["title"] == "NoSQL Injection"
    assert rows[0]["file"] == "routes/index.js"
    assert rows[0]["lines"] == "39-39"
    assert rows[0]["source_ignore_type"] == "wont-fix"


def test_csv_sorts_actionable_first(tmp_path: Path):
    plan = {
        "actions": [
            _action(status="already_migrated", source_policy_id="m"),
            _action(status="would_create", source_policy_id="c"),
            _action(status="already_ignored_in_destination", source_policy_id="i"),
            _action(status="would_patch", type="patch_project_metadata", source_policy_id="p"),
        ]
    }
    p = _write_plan_csv(plan, tmp_path / "apply_plan.csv")
    statuses = [r["status"] for r in _read_csv(p)]
    assert statuses == [
        "would_create",
        "would_patch",
        "already_migrated",
        "already_ignored_in_destination",
    ]


def test_csv_truncates_long_reason(tmp_path: Path):
    long = "x" * 500
    plan = {"actions": [_action(source_reason=long)]}
    p = _write_plan_csv(plan, tmp_path / "apply_plan.csv")
    row = _read_csv(p)[0]
    assert len(row["source_reason"]) <= 200
    assert row["source_reason"].endswith("…")


def test_csv_handles_missing_signature(tmp_path: Path):
    plan = {"actions": [_action(signature=None)]}
    p = _write_plan_csv(plan, tmp_path / "apply_plan.csv")
    row = _read_csv(p)[0]
    assert row["title"] == ""
    assert row["file"] == ""
    assert row["lines"] == ""


def test_csv_joins_notes_with_pipe(tmp_path: Path):
    plan = {"actions": [_action(notes=["first note", "second note"])]}
    p = _write_plan_csv(plan, tmp_path / "apply_plan.csv")
    row = _read_csv(p)[0]
    assert row["notes"] == "first note | second note"
