"""Unit tests for apply._decide_policy_action_status.

Covers the five decision branches:
  1. our breadcrumb matches → already_migrated
  2. issue ignored + dst policy w/o our breadcrumb → already_ignored_in_destination
  3. issue ignored + no dst policy → already_ignored_via_higher_scope_policy
  4. issue not ignored + no dst policy → would_create
  5. issue not ignored + dangling dst policy → would_create (with note)
"""
from __future__ import annotations

from ado_gh_migration.stages.apply import _decide_policy_action_status


def _policy(reason: str, asset_uuid: str = "NEW", review: str = "approved") -> dict:
    return {
        "id": f"dst-{reason}",
        "attributes": {
            "review": review,
            "action": {"data": {"reason": reason}},
            "conditions_group": {
                "conditions": [{"value": asset_uuid}],
            },
        },
    }


def test_breadcrumb_match_is_already_migrated():
    breadcrumbed = _policy(
        "[migrated from azure: u; old-policy-id: src-1]"
    )
    status, ours, notes = _decide_policy_action_status(
        dst_issue_ignored=True, dst_ka_policies=[breadcrumbed], src_policy_id="src-1"
    )
    assert status == "already_migrated"
    assert ours is breadcrumbed
    assert notes == []


def test_breadcrumb_match_wins_even_if_issue_not_ignored():
    """Once we've migrated, idempotency must hold regardless of the policy's current effective state
    (e.g. user later rejected the migrated policy)."""
    breadcrumbed = _policy(
        "[migrated from azure: u; old-policy-id: src-1]", review="rejected"
    )
    status, _, _ = _decide_policy_action_status(
        dst_issue_ignored=False, dst_ka_policies=[breadcrumbed], src_policy_id="src-1"
    )
    assert status == "already_migrated"


def test_issue_ignored_with_other_policy_is_already_ignored_in_destination():
    manual = _policy("manual ignore via UI")
    status, ours, _ = _decide_policy_action_status(
        dst_issue_ignored=True, dst_ka_policies=[manual], src_policy_id="src-1"
    )
    assert status == "already_ignored_in_destination"
    assert ours is None


def test_issue_ignored_with_no_policy_is_higher_scope():
    """The issue is reported as ignored but no org-level policy references it →
    a group-level Snyk Code Security Policy must be applying."""
    status, _, _ = _decide_policy_action_status(
        dst_issue_ignored=True, dst_ka_policies=[], src_policy_id="src-1"
    )
    assert status == "already_ignored_via_higher_scope_policy"


def test_issue_not_ignored_clean_creates():
    status, _, notes = _decide_policy_action_status(
        dst_issue_ignored=False, dst_ka_policies=[], src_policy_id="src-1"
    )
    assert status == "would_create"
    assert notes == []


def test_issue_not_ignored_with_dangling_policies_creates_with_note():
    """The bug we hit: old rejected/expired policies referencing the same asset must
    NOT block creation when the issue isn't currently being ignored."""
    rejected = _policy("CLItest", review="rejected")
    pending = _policy("reymund", review="pending")
    status, _, notes = _decide_policy_action_status(
        dst_issue_ignored=False,
        dst_ka_policies=[rejected, pending],
        src_policy_id="src-1",
    )
    assert status == "would_create"
    assert len(notes) == 1
    assert "dangling" in notes[0]
    assert "2" in notes[0]


def test_issue_ignored_unknown_treated_as_not_ignored():
    """If issue lookup returns None (state inconsistency), don't block creation."""
    status, _, _ = _decide_policy_action_status(
        dst_issue_ignored=None, dst_ka_policies=[], src_policy_id="src-1"
    )
    assert status == "would_create"
