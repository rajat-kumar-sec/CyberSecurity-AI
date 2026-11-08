"""Executor tests: preview, approval binding, replay, cancel and rollback.

Every state-changing action goes through ``FakeElevation``. No real Windows
Firewall command is ever run.
"""

import pytest

from defense import policy
from defense.models import (
    ActionCancelled,
    ActionError,
    ActionExpired,
    ApprovalExpired,
    ApprovalInvalid,
    ApprovalRequired,
    DefenseError,
    DuplicateExecution,
    UnknownActionError,
)
from defense_support import (
    VALID_BLOCK,
    Clock,
    Completed,
    FakeElevation,
    make_service,
)


def preview_block(service, params=None):
    return service.preview("create_firewall_block_rule", params or VALID_BLOCK)


def execute_flow(service, params=None):
    preview = preview_block(service, params)
    action_id = preview["action"]["action_id"]
    approval = service.approve(action_id, "create_firewall_block_rule")
    result = service.execute(action_id, approval["approval_token"])
    return action_id, approval, result


# ----------------------------------------------------------------- preview


def test_preview_returns_a_bound_action_and_no_side_effects(tmp_path):
    clock = Clock()
    elevation = FakeElevation()
    service = make_service(tmp_path, clock, elevation=elevation)

    data = preview_block(service)

    action = data["action"]
    preview = data["preview"]
    assert action["action_type"] == "create_firewall_block_rule"
    assert action["status"] == "pending"
    assert preview["requires_admin"] is True
    assert preview["rollback_supported"] is True
    assert "203.0.113.7" in preview["target"]
    assert preview["params"]["remote_address"] == "203.0.113.7/32"
    # Dry run: nothing was elevated and no rule was recorded.
    assert elevation.calls == []
    assert service.rules.list_active() == []


def test_preview_unknown_action_is_rejected(tmp_path):
    service = make_service(tmp_path, Clock())

    with pytest.raises(UnknownActionError):
        service.preview("terminate_process", {})


def test_preview_invalid_parameters_are_rejected(tmp_path):
    service = make_service(tmp_path, Clock())

    with pytest.raises(DefenseError):
        service.preview(
            "create_firewall_block_rule", {"remote_address": "not-an-ip"}
        )


def test_preview_remove_requires_a_recorded_rule(tmp_path):
    service = make_service(tmp_path, Clock())

    with pytest.raises(DefenseError):
        service.preview(
            "remove_cyberguard_firewall_rule",
            {"rule_name": "CyberGuard-Block-In-TCP-abcdef0123"},
        )


# ---------------------------------------------------------------- approval


def test_execution_without_approval_is_rejected(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = preview_block(service)["action"]["action_id"]

    with pytest.raises(ApprovalRequired):
        service.execute(action_id, None)

    assert service.rules.list_active() == []


def test_approval_requires_the_exact_action_type_as_confirmation(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = preview_block(service)["action"]["action_id"]

    for wrong in (None, "", "yes", "remove_cyberguard_firewall_rule"):
        with pytest.raises(DefenseError) as error:
            service.approve(action_id, wrong)
        assert error.value.error_category == "approval_invalid"


def test_read_only_actions_need_no_approval(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = service.preview("list_processes", {})["action"]["action_id"]

    with pytest.raises(ActionError) as error:
        service.approve(action_id, "list_processes")
    assert error.value.error_category == "approval_not_required"


def test_approval_replaces_an_earlier_token(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = preview_block(service)["action"]["action_id"]

    first = service.approve(action_id, "create_firewall_block_rule")
    second = service.approve(action_id, "create_firewall_block_rule")

    with pytest.raises(ApprovalInvalid):
        service.execute(action_id, first["approval_token"])

    result = service.execute(action_id, second["approval_token"])
    assert result["status"] == "success"


def test_approval_expires(tmp_path):
    clock = Clock()
    service = make_service(tmp_path, clock)
    action_id = preview_block(service)["action"]["action_id"]
    approval = service.approve(action_id, "create_firewall_block_rule")

    clock.advance(301)

    with pytest.raises(ApprovalExpired):
        service.execute(action_id, approval["approval_token"])
    assert service.rules.list_active() == []


def test_prepared_action_expires(tmp_path):
    clock = Clock()
    service = make_service(tmp_path, clock)
    action_id = preview_block(service)["action"]["action_id"]

    clock.advance(901)

    with pytest.raises(ActionExpired):
        service.execute(action_id, None)


def test_parameter_tampering_invalidates_the_approval(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = preview_block(service)["action"]["action_id"]
    approval = service.approve(action_id, "create_firewall_block_rule")

    stored = service.actions.get(action_id)
    stored.params["remote_address"] = "198.51.100.9/32"

    with pytest.raises(ApprovalInvalid):
        service.execute(action_id, approval["approval_token"])
    assert service.rules.list_active() == []


# ---------------------------------------------------------------- execution


def test_full_flow_executes_once_and_records_ownership(tmp_path):
    clock = Clock()
    elevation = FakeElevation()
    service = make_service(tmp_path, clock, elevation=elevation)

    action_id, approval, result = execute_flow(service)

    assert result["status"] == "success"
    assert result["changed"] is True
    assert result["verified"] is True
    assert result["elevation"] == "used"
    assert result["rollback_available"] is True
    assert len(elevation.calls) == 1
    assert elevation.calls[0][0] == "create_firewall_block_rule"

    active = service.rules.list_active()
    assert len(active) == 1
    assert active[0]["rule_name"] == policy.rule_name_for(
        policy.validate_action("create_firewall_block_rule", VALID_BLOCK)
    )
    assert active[0]["action_id"] == action_id


def test_replay_after_success_is_rejected(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id, approval, result = execute_flow(service)
    assert result["status"] == "success"

    with pytest.raises(DuplicateExecution):
        service.execute(action_id, approval["approval_token"])


def test_a_used_token_cannot_be_reused_for_a_fresh_action(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id, approval, _ = execute_flow(service)

    # Same id cannot be replayed at all.
    with pytest.raises(DuplicateExecution):
        service.execute(action_id, approval["approval_token"])


def test_cancelled_action_never_executes(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = preview_block(service)["action"]["action_id"]
    service.approve(action_id, "create_firewall_block_rule")

    service.cancel(action_id)

    with pytest.raises(ActionCancelled):
        service.execute(action_id, None)
    assert service.rules.list_active() == []


def test_cancelling_after_execution_is_rejected(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id, _, _ = execute_flow(service)

    with pytest.raises(DuplicateExecution):
        service.cancel(action_id)


def test_elevation_disabled_reports_failure_and_changes_nothing(tmp_path):
    elevation = FakeElevation(result={
        "status": "failure",
        "changed": False,
        "verified": False,
        "error": "The Windows elevation adapter is disabled.",
        "error_category": "elevation_disabled",
        "elevation": "disabled",
        "detail": {},
    })
    service = make_service(tmp_path, Clock(), elevation=elevation)

    _, _, result = execute_flow(service)

    assert result["status"] == "failure"
    assert result["changed"] is False
    assert result["error_category"] == "elevation_disabled"
    assert result["rollback_available"] is False
    assert service.rules.list_active() == []


def test_elevation_failure_is_recorded_without_ownership(tmp_path):
    elevation = FakeElevation(result={
        "status": "failure",
        "changed": False,
        "verified": False,
        "error": "netsh failed",
        "error_category": "firewall_command_failed",
        "elevation": "used",
        "detail": {},
    })
    service = make_service(tmp_path, Clock(), elevation=elevation)

    _, _, result = execute_flow(service)

    assert result["status"] == "failure"
    assert result["error_category"] == "firewall_command_failed"
    assert service.rules.list_active() == []


def test_idempotent_success_does_not_record_a_new_owner(tmp_path):
    elevation = FakeElevation(result={
        "status": "success",
        "changed": False,
        "verified": True,
        "error": None,
        "error_category": None,
        "elevation": "used",
        "detail": {"already_exists": True},
    })
    service = make_service(tmp_path, Clock(), elevation=elevation)

    _, _, result = execute_flow(service)

    assert result["status"] == "success"
    assert result["changed"] is False
    assert service.rules.list_active() == []


def test_ownership_record_failure_does_not_fake_a_failure(tmp_path, monkeypatch):
    service = make_service(tmp_path, Clock())

    def broken_upsert(record):
        raise OSError("disk full")

    monkeypatch.setattr(service.rules, "upsert", broken_upsert)

    _, _, result = execute_flow(service)

    # The firewall change really happened, so the action is a success; but
    # rollback must not be claimed because ownership was not recorded.
    assert result["status"] == "success"
    assert result["changed"] is True
    assert result["rollback_available"] is False
    assert result["rollback_status"] == "unavailable"
    assert result["detail"]["ownership_error"] == "OSError"


# --------------------------------------------------------------- read only


def test_read_only_inspection_runs_without_elevation(tmp_path):
    elevation = FakeElevation()
    service = make_service(tmp_path, Clock(), elevation=elevation)
    action_id = service.preview("list_processes", {"limit": 5})["action"][
        "action_id"
    ]

    result = service.execute(action_id)

    assert result["status"] == "success"
    assert result["changed"] is False
    assert result["detail"]["count"] == 2
    assert result["detail"]["processes"][0]["name"] == "chrome.exe"
    assert elevation.calls == []


def test_preview_firewall_action_changes_nothing(tmp_path):
    elevation = FakeElevation()
    service = make_service(tmp_path, Clock(), elevation=elevation)
    action_id = service.preview(
        "preview_firewall_block_rule", VALID_BLOCK
    )["action"]["action_id"]

    result = service.execute(action_id)

    assert result["status"] == "success"
    assert result["changed"] is False
    assert result["detail"]["state_changed"] is False
    assert result["detail"]["rule_name"].startswith("CyberGuard-")
    assert elevation.calls == []


def test_incident_report_writes_no_file(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = service.preview(
        "generate_incident_report", {"title": "Test incident", "risk": "high"}
    )["action"]["action_id"]

    result = service.execute(action_id)

    assert result["status"] == "success"
    assert result["detail"]["title"] == "Test incident"
    assert result["detail"]["risk"] == "HIGH"
    files = {path.name for path in (tmp_path / "defense").glob("*")}
    assert files <= {"audit.jsonl", "audit.jsonl.1"}


def test_inspect_rejects_state_changing_actions(tmp_path):
    service = make_service(tmp_path, Clock())

    with pytest.raises(DefenseError):
        service.inspect("create_firewall_block_rule", VALID_BLOCK)


def test_inspection_command_failure_is_reported(tmp_path):
    def failing(argv, **kwargs):
        if str(argv[0]).lower().endswith("tasklist.exe") or argv[0] == "tasklist":
            return Completed.fail(1, "access denied")
        return Completed.ok("")

    service = make_service(
        tmp_path, Clock(), inspection_runner=failing
    )

    result = service.inspect("list_processes", {})

    assert result["available"] is False
    assert result["error_category"] == "command_failed"


def test_execution_of_a_failed_inspection_reports_failure(tmp_path):
    def failing(argv, **kwargs):
        return Completed.fail(1, "access denied")

    service = make_service(
        tmp_path, Clock(), inspection_runner=failing
    )
    action_id = service.preview("list_processes", {})["action"]["action_id"]

    result = service.execute(action_id)

    assert result["status"] == "failure"
    assert result["error_category"] == "command_failed"


# ---------------------------------------------------------------- rollback


def test_rollback_is_prepared_but_not_executed(tmp_path):
    elevation = FakeElevation()
    service = make_service(tmp_path, clock=Clock(), elevation=elevation)
    action_id, _, _ = execute_flow(service)
    calls_before = list(elevation.calls)

    rollback = service.prepare_rollback(action_id)

    assert rollback["action"]["action_type"] == (
        "remove_cyberguard_firewall_rule"
    )
    assert rollback["action"]["params"]["rule_name"].startswith("CyberGuard-")
    assert rollback["preview"]["requires_admin"] is True
    assert elevation.calls == calls_before
    assert len(service.rules.list_active()) == 1


def test_rollback_can_be_approved_and_executed(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id, _, _ = execute_flow(service)
    prepared = service.prepare_rollback(action_id)

    remove_id = prepared["action"]["action_id"]
    approval = service.approve(
        remove_id, "remove_cyberguard_firewall_rule"
    )
    result = service.execute(remove_id, approval["approval_token"])

    assert result["status"] == "success"
    assert result["changed"] is True
    assert service.rules.list_active() == []
    assert len(service.rules.list_removed()) == 1


def test_remove_rollback_recreates_the_original_rule(tmp_path):
    service = make_service(tmp_path, Clock())
    create_id, _, _ = execute_flow(service)

    remove_preview = service.preview(
        "remove_cyberguard_firewall_rule",
        {"rule_name": service.rules.list_active()[0]["rule_name"]},
    )
    remove_id = remove_preview["action"]["action_id"]
    approval = service.approve(
        remove_id, "remove_cyberguard_firewall_rule"
    )
    service.execute(remove_id, approval["approval_token"])
    assert service.rules.list_active() == []

    prepared = service.prepare_rollback(remove_id)

    assert prepared["action"]["action_type"] == "create_firewall_block_rule"
    assert prepared["action"]["params"]["remote_address"] == (
        "203.0.113.7/32"
    )
    assert prepared["action"]["params"]["local_port"] == "22"


def test_rollback_of_read_only_action_is_not_applicable(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = service.preview("list_processes", {})["action"]["action_id"]

    with pytest.raises(ActionError) as error:
        service.prepare_rollback(action_id)
    assert error.value.error_category == "rollback_not_applicable"


def test_rollback_without_an_ownership_record_is_unavailable(tmp_path):
    elevation = FakeElevation(result={
        "status": "success",
        "changed": False,
        "verified": True,
        "error": None,
        "error_category": None,
        "elevation": "used",
        "detail": {},
    })
    service = make_service(tmp_path, Clock(), elevation=elevation)
    action_id, _, _ = execute_flow(service)

    with pytest.raises(ActionError) as error:
        service.prepare_rollback(action_id)
    assert error.value.error_category == "rollback_unavailable"


def test_rollback_of_another_actions_rule_is_refused(tmp_path):
    service = make_service(tmp_path, Clock())
    first_id, _, _ = execute_flow(service)

    # A second action for the same rule is idempotent: the fake helper reports
    # no change, so the second action owns nothing.
    second = service.preview("create_firewall_block_rule", VALID_BLOCK)
    second_id = second["action"]["action_id"]
    service.elevation.result = {
        "status": "success",
        "changed": False,
        "verified": True,
        "error": None,
        "error_category": None,
        "elevation": "used",
        "detail": {"already_exists": True},
    }
    approval = service.approve(second_id, "create_firewall_block_rule")
    service.execute(second_id, approval["approval_token"])

    with pytest.raises(ActionError) as error:
        service.prepare_rollback(second_id)
    assert error.value.error_category in (
        "rollback_unavailable", "rollback_not_owned"
    )

    # The original owner can still roll back.
    prepared = service.prepare_rollback(first_id)
    assert prepared["action"]["action_type"] == (
        "remove_cyberguard_firewall_rule"
    )


# ------------------------------------------------------------------- audit


def test_audit_contains_preview_approval_and_execution_without_token(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id, approval, _ = execute_flow(service)

    events = service.audit_events(50)["events"]
    kinds = [event["event_type"] for event in events]
    assert kinds[:3] == ["execution", "approval", "preview"]

    raw = (tmp_path / "defense" / "audit.jsonl").read_text(encoding="utf-8")
    assert approval["approval_token"] not in raw
    assert "approval_token" not in raw
    assert action_id in raw


def test_cancellation_is_audited(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = preview_block(service)["action"]["action_id"]

    service.cancel(action_id)

    events = service.audit_events(10)["events"]
    assert events[0]["event_type"] == "cancellation"
    assert events[0]["outcome"] == "cancelled"


def test_rejected_execution_is_audited(tmp_path):
    service = make_service(tmp_path, Clock())
    action_id = preview_block(service)["action"]["action_id"]

    with pytest.raises(ApprovalRequired):
        service.execute(action_id, None)

    events = service.audit_events(10)["events"]
    assert events[0]["event_type"] == "execution"
    assert events[0]["outcome"] == "rejected"
    assert events[0]["error_category"] == "approval_required"


def test_status_reports_capabilities_and_limitations(tmp_path):
    service = make_service(tmp_path, Clock())
    status = service.status()

    assert status["available"] is True
    assert len(status["actions"]) == 7
    assert any("Process termination" in item for item in status["limitations"])
