"""Unit tests for the apply stage's _propose_policy_body builder.

Snyk's POST schema for policies is stricter than the GET shape: some fields
that are nullable on GET (e.g. `expires`) are non-nullable on POST and must
be omitted when empty. Lock that down here.
"""
from __future__ import annotations

from ado_gh_migration.stages.apply import _propose_policy_body


def _src_policy(**overrides) -> dict:
    base_attrs: dict = {
        "name": "Ignore Issue X",
        "review": "approved",
        "action_type": "ignore",
        "action": {"data": {"ignore_type": "wont-fix", "reason": "test", "expires": None}},
        "conditions_group": {
            "logical_operator": "and",
            "conditions": [
                {"field": "snyk/asset/finding/v1", "operator": "includes", "value": "OLD"}
            ],
        },
    }
    base_attrs.update(overrides)
    return {"id": "src-1", "type": "policy", "attributes": base_attrs}


def test_expires_omitted_when_null():
    body = _propose_policy_body(_src_policy(), "NEW", "[migrated from azure: x; old-policy-id: src-1]")
    action_data = body["data"]["attributes"]["action"]["data"]
    assert "expires" not in action_data, "Snyk POST rejects null expires; field must be absent"


def test_expires_passed_through_when_set():
    src = _src_policy(action={"data": {"ignore_type": "temporary-ignore", "reason": "r", "expires": "2026-12-31T00:00:00Z"}})
    body = _propose_policy_body(src, "NEW", "bc")
    assert body["data"]["attributes"]["action"]["data"]["expires"] == "2026-12-31T00:00:00Z"


def test_breadcrumb_appended_to_reason():
    body = _propose_policy_body(_src_policy(), "NEW", "[migrated from azure: u; old-policy-id: src-1]")
    reason = body["data"]["attributes"]["action"]["data"]["reason"]
    assert reason.startswith("test")
    assert "[migrated from azure: u; old-policy-id: src-1]" in reason


def test_breadcrumb_is_only_content_when_reason_empty():
    src = _src_policy(action={"data": {"ignore_type": "wont-fix", "reason": "", "expires": None}})
    body = _propose_policy_body(src, "NEW", "[migrated from azure: u; old-policy-id: src-1]")
    assert body["data"]["attributes"]["action"]["data"]["reason"] == "[migrated from azure: u; old-policy-id: src-1]"


def test_condition_value_uses_new_asset():
    body = _propose_policy_body(_src_policy(), "NEW-ASSET-UUID", "bc")
    cond = body["data"]["attributes"]["conditions_group"]["conditions"][0]
    assert cond["value"] == "NEW-ASSET-UUID"
    assert cond["field"] == "snyk/asset/finding/v1"


def test_review_is_never_included():
    """Snyk POST schema (additionalProperties: false) rejects `review`; it must be absent."""
    body = _propose_policy_body(_src_policy(), "NEW", "bc")
    assert "review" not in body["data"]["attributes"]


def test_name_passed_through_when_set():
    body = _propose_policy_body(_src_policy(), "NEW", "bc")
    assert body["data"]["attributes"]["name"] == "Ignore Issue X"


def test_name_falls_back_when_source_has_none():
    src = _src_policy(name="")
    body = _propose_policy_body(src, "NEW-ASSET", "bc")
    # `name` is required by the POST schema, so we must always send something.
    assert body["data"]["attributes"]["name"] == "Migrated ignore for NEW-ASSET"


def test_only_schema_allowed_top_level_keys_present():
    """The CreatePolicyPayload schema is closed (additionalProperties: false).
    Confirm we send only keys it allows."""
    body = _propose_policy_body(_src_policy(), "NEW", "bc")
    allowed = {"action", "action_type", "conditions_group", "name", "source"}
    actual = set(body["data"]["attributes"].keys())
    extra = actual - allowed
    assert not extra, f"sent keys not allowed by Snyk POST schema: {extra}"
