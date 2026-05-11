"""Live-execution path tests for apply.execute_plan, using respx to mock Snyk."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from ado_gh_migration.stages.apply import execute_plan


@pytest.fixture(autouse=True)
def _token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SNYK_TOKEN", "test-token")


def _plan(actions: list[dict]) -> dict:
    return {
        "planned_at": "2024-01-01T00:00:00+00:00",
        "group_id": "g1",
        "org_id": "o1",
        "summary": {},
        "actions": actions,
    }


@respx.mock
def test_execute_plan_creates_policy_and_writes_results(tmp_path: Path):
    body = {"data": {"type": "policy", "attributes": {"name": "x"}}}
    new_policy = {"data": {"id": "new-policy-uuid", "type": "policy"}}

    route = respx.post("https://api.snyk.io/rest/orgs/o1/policies").mock(
        return_value=httpx.Response(201, json=new_policy)
    )

    plan = _plan([
        {
            "type": "create_policy",
            "status": "would_create",
            "source_policy_id": "old-1",
            "old_key_asset": "AAA",
            "new_key_asset": "BBB",
            "proposed_body": body,
        }
    ])

    results = execute_plan(plan, "g1", "o1", region="us", api_version="2026-01-01", state_root=tmp_path)

    assert route.called
    assert results["summary"]["created"] == 1
    assert results["summary"]["failed"] == 0
    assert results["actions"][0]["execution_status"] == "created"
    assert results["actions"][0]["created_policy_id"] == "new-policy-uuid"
    saved = json.loads((tmp_path / "g1" / "o1" / "apply_results.json").read_text())
    assert saved["summary"]["created"] == 1


@respx.mock
def test_execute_plan_skips_non_actionable_status(tmp_path: Path):
    plan = _plan([
        {"type": "create_policy", "status": "already_migrated", "source_policy_id": "x"},
        {"type": "create_policy", "status": "unmappable", "source_policy_id": "y"},
        {"type": "create_policy", "status": "already_ignored_in_destination", "source_policy_id": "z"},
    ])

    results = execute_plan(plan, "g1", "o1", region="us", api_version="2026-01-01", state_root=tmp_path)

    assert results["summary"]["skipped"] == 3
    assert results["summary"]["failed"] == 0
    assert results["summary"]["created"] == 0
    for a in results["actions"]:
        assert a["execution_status"] == "skipped"


@respx.mock
def test_execute_plan_records_failure_with_response_body(tmp_path: Path):
    error_payload = {"errors": [{"detail": "Validation failed"}]}
    respx.post("https://api.snyk.io/rest/orgs/o1/policies").mock(
        return_value=httpx.Response(400, json=error_payload)
    )

    plan = _plan([
        {
            "type": "create_policy",
            "status": "would_create",
            "source_policy_id": "old-1",
            "proposed_body": {"data": {}},
        }
    ])

    results = execute_plan(plan, "g1", "o1", region="us", api_version="2026-01-01", state_root=tmp_path)

    assert results["summary"]["failed"] == 1
    assert results["summary"]["created"] == 0
    a = results["actions"][0]
    assert a["execution_status"] == "failed"
    assert a["error_response"] == error_payload


@respx.mock
def test_execute_plan_continues_after_one_failure(tmp_path: Path):
    """One failed action shouldn't abort the rest of the plan."""
    respx.post("https://api.snyk.io/rest/orgs/o1/policies").mock(
        side_effect=[
            httpx.Response(400, json={"errors": [{"detail": "first fails"}]}),
            httpx.Response(201, json={"data": {"id": "second-id"}}),
        ]
    )

    plan = _plan([
        {"type": "create_policy", "status": "would_create", "source_policy_id": "a", "proposed_body": {"data": {}}},
        {"type": "create_policy", "status": "would_create", "source_policy_id": "b", "proposed_body": {"data": {}}},
    ])

    results = execute_plan(plan, "g1", "o1", region="us", api_version="2026-01-01", state_root=tmp_path)

    assert results["summary"]["created"] == 1
    assert results["summary"]["failed"] == 1
    assert results["summary"]["skipped"] == 0


@respx.mock
def test_execute_plan_409_treated_as_already_exists(tmp_path: Path):
    """Snyk returns 409 when a policy with the same conditions already exists.
    That's the idempotent goal of the migration, not a failure — record it as
    already_exists so the operator sees the staleness without alarm."""
    error_payload = {"errors": [{"detail": "Policy already exists"}]}
    respx.post("https://api.snyk.io/rest/orgs/o1/policies").mock(
        return_value=httpx.Response(409, json=error_payload)
    )

    plan = _plan([
        {
            "type": "create_policy",
            "status": "would_create",
            "source_policy_id": "src-1",
            "proposed_body": {"data": {}},
        }
    ])

    results = execute_plan(plan, "g1", "o1", region="us", api_version="2026-01-01", state_root=tmp_path)

    assert results["summary"]["already_exists"] == 1
    assert results["summary"]["failed"] == 0
    a = results["actions"][0]
    assert a["execution_status"] == "already_exists"
    assert a["error_response"] == error_payload
    assert "stale" in (a.get("notes") or [""])[0].lower()


@respx.mock
def test_execute_plan_patches_project(tmp_path: Path):
    respx.patch("https://api.snyk.io/rest/orgs/o1/projects/proj-1").mock(
        return_value=httpx.Response(200, json={"data": {"id": "proj-1"}})
    )

    plan = _plan([
        {
            "type": "patch_project_metadata",
            "status": "would_patch",
            "destination_project_id": "proj-1",
            "proposed_patch": {"data": {"attributes": {"tags": [{"key": "team", "value": "x"}]}}},
        }
    ])

    results = execute_plan(plan, "g1", "o1", region="us", api_version="2026-01-01", state_root=tmp_path)

    assert results["summary"]["patched"] == 1
    assert results["actions"][0]["execution_status"] == "patched"
