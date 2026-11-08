"""Tests for the typed defense models and error taxonomy."""

import re
import time

import pytest

from defense import models
from defense.models import (
    ActionCancelled,
    ActionExpired,
    ActionNotFound,
    ActionPreview,
    ActionRequest,
    Approval,
    ApprovalExpired,
    ApprovalInvalid,
    ApprovalRequired,
    ApprovalUsed,
    AuditEvent,
    DefenseError,
    DuplicateExecution,
    ElevationError,
    ExecutionResult,
    PolicyError,
    UnknownActionError,
    canonical_json,
    iso,
    new_id,
    params_hash,
    token_hash,
    utc_now,
)


def make_action(**overrides):
    now = 1_700_000_000.0
    values = dict(
        action_id=new_id(),
        action_type="create_firewall_block_rule",
        params={"remote_address": "203.0.113.7/32"},
        target="Windows Firewall",
        risk="medium",
        requires_admin=True,
        rollback_supported=True,
        created_at=now,
        expires_at=now + 60,
        params_hash=params_hash({"remote_address": "203.0.113.7/32"}),
    )
    values.update(overrides)
    return ActionRequest(**values)


def test_canonical_json_is_order_independent():
    left = {"b": 2, "a": [1, {"y": True, "x": None}]}
    right = {"a": [1, {"x": None, "y": True}], "b": 2}

    assert canonical_json(left) == canonical_json(right)
    assert canonical_json(left) == '{"a":[1,{"x":null,"y":true}],"b":2}'


def test_canonical_json_ascii_only():
    assert canonical_json({"name": "caf\u00e9"}) == '{"name":"caf\\u00e9"}'


def test_params_hash_changes_when_a_value_changes():
    first = params_hash({"port": 22, "protocol": "tcp"})
    second = params_hash({"port": 23, "protocol": "tcp"})

    assert first != second
    assert re.fullmatch(r"[a-f0-9]{64}", first)


def test_token_hash_never_returns_the_token():
    token = "super-secret-approval-token"
    digest = token_hash(token)

    assert token not in digest
    assert digest == token_hash(token)
    assert digest != token_hash(token + "x")


def test_new_id_is_unpredictable_hex_and_unique():
    values = {new_id() for _ in range(50)}

    assert len(values) == 50
    for value in values:
        assert re.fullmatch(r"[a-f0-9]{32}", value)


def test_iso_renders_utc_with_offset():
    rendered = iso(0)

    assert rendered.startswith("1970-01-01T00:00:00")
    assert rendered.endswith("+00:00")


def test_utc_now_is_timezone_aware():
    assert utc_now().tzinfo is not None


@pytest.mark.parametrize(
    "error, category, status",
    [
        (UnknownActionError("x"), "unknown_action", 400),
        (PolicyError("x"), "invalid_parameters", 400),
        (ActionNotFound("x"), "action_not_found", 404),
        (ActionExpired("x"), "action_expired", 409),
        (ActionCancelled("x"), "action_cancelled", 409),
        (DuplicateExecution("x"), "already_executed", 409),
        (ApprovalRequired("x"), "approval_required", 409),
        (ApprovalInvalid("x"), "approval_invalid", 409),
        (ApprovalExpired("x"), "approval_expired", 409),
        (ApprovalUsed("x"), "approval_used", 409),
        (ElevationError("x"), "elevation_failed", 409),
    ],
)
def test_error_taxonomy(error, category, status):
    assert error.error_category == category
    assert error.http_status == status
    payload = error.to_dict()
    assert payload["error"] == "x"
    assert payload["error_category"] == category


def test_error_includes_action_id_only_when_present():
    assert "action_id" not in DefenseError("x").to_dict()
    assert DefenseError("x", action_id="a" * 32).to_dict()["action_id"] == "a" * 32


def test_action_request_to_dict_has_no_hash():
    action = make_action()
    data = action.to_dict()

    assert data["action_id"] == action.action_id
    assert data["params"] == action.params
    assert "params_hash" not in data
    assert data["expires_at"].endswith("+00:00")


def test_action_preview_to_dict_round_trips_safe_fields():
    now = time.time()
    preview = ActionPreview(
        action_id="a" * 32,
        action_type="create_firewall_block_rule",
        title="Create",
        target="Windows Firewall",
        params={"protocol": "tcp"},
        expected_effect="Creates one rule.",
        risk="medium",
        requires_admin=True,
        rollback_supported=True,
        warnings=["w"],
        created_at=now,
        expires_at=now + 10,
    )
    data = preview.to_dict()

    assert data["action_id"] == "a" * 32
    assert data["warnings"] == ["w"]
    assert data["idempotent"] is False


def test_approval_public_dict_hides_the_hash():
    approval = Approval(
        approval_id="b" * 32,
        action_id="a" * 32,
        action_type="create_firewall_block_rule",
        params_hash="h" * 64,
        issued_at=1.0,
        expires_at=2.0,
        token_hash="secret-hash",
    )
    public = approval.public_dict()

    assert public["single_use"] is True
    assert "token_hash" not in public
    assert "secret-hash" not in str(public)


def test_execution_result_to_dict_is_json_safe():
    result = ExecutionResult(
        action_id="a" * 32,
        action_type="list_processes",
        status="success",
        changed=False,
        approval="not_required",
        elevation="not_required",
        verified=True,
    )
    data = result.to_dict()

    assert data["status"] == "success"
    assert data["verified"] is True
    assert data["detail"] == {}


def test_audit_event_to_dict_uses_fixed_schema():
    event = AuditEvent(
        event_type="execution",
        action_id="a" * 32,
        action_type="list_processes",
        target="process table",
        params_summary={"limit": 10},
        approval="not_required",
        outcome="success",
    )
    data = event.to_dict()

    assert set(data) == {
        "timestamp", "event_type", "action_id", "action_type", "target",
        "params_summary", "approval", "outcome", "error_category",
        "elevation", "rollback_available", "rollback_status",
    }
    assert data["rollback_available"] is False
    assert data["error_category"] is None
