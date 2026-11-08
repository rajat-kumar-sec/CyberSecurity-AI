"""Audit log tests: sanitization, append-only reads and rotation."""

import json

import pytest

from defense.audit import AuditLog, sanitize_event
from defense.models import AuditEvent
from defense_support import Clock


def make_event(**overrides):
    values = dict(
        event_type="execution",
        action_id="a" * 32,
        action_type="create_firewall_block_rule",
        target="Windows Firewall",
        params_summary={
            "remote_address": "203.0.113.7/32",
            "lifetime_minutes": 60,
        },
        approval="granted",
        outcome="success",
        elevation="used",
        rollback_available=True,
        rollback_status="available",
    )
    values.update(overrides)
    return AuditEvent(**values)


def test_sanitize_drops_forbidden_and_unknown_keys():
    event = make_event(
        params_summary={
            "remote_address": "203.0.113.7/32",
            "approval_token": "secret-token",
            "password": "hunter2",
            "notes": "private note",
            "description": "private detail",
            "unknown": "value",
        }
    )
    data = sanitize_event(event)

    assert data["params_summary"] == {"remote_address": "203.0.113.7/32"}
    serialized = json.dumps(data)
    assert "secret-token" not in serialized
    assert "hunter2" not in serialized
    assert "private note" not in serialized


def test_record_appends_one_line_and_reads_newest_first(tmp_path):
    clock = Clock()
    log = AuditLog(tmp_path / "audit.jsonl", clock=clock)

    log.record(make_event(outcome="first"))
    clock.advance(1)
    log.record(make_event(outcome="second"))

    assert log.count() == 2
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    events = log.read(10)
    assert [event["outcome"] for event in events] == ["second", "first"]


def test_read_limit_is_honoured_and_clamped(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for index in range(5):
        log.record(make_event(outcome=f"e{index}"))

    assert len(log.read(2)) == 2
    assert len(log.read(0)) == 1
    assert len(log.read(10_000)) == 5
    assert log.read("not-a-number")[0]["outcome"] == "e4"


def test_malformed_lines_are_skipped(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"broken": \nnot json\n\n', encoding="utf-8")
    log = AuditLog(path)

    assert log.read(10) == []
    log.record(make_event(outcome="good"))
    events = log.read(10)
    assert len(events) == 1
    assert events[0]["outcome"] == "good"


def test_rotation_keeps_a_bounded_history(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, max_bytes=1)

    log.record(make_event(outcome="first"))
    log.record(make_event(outcome="second"))

    rotated = tmp_path / "audit.jsonl.1"
    assert rotated.exists()
    assert "first" in rotated.read_text(encoding="utf-8")
    assert "first" not in path.read_text(encoding="utf-8")
    assert log.read(10)[0]["outcome"] == "second"


def test_record_action_uses_safe_parameter_summary(tmp_path):
    class Action:
        action_id = "a" * 32
        action_type = "create_firewall_block_rule"
        target = "Windows Firewall"
        params = {
            "remote_address": "203.0.113.7/32",
            "description": "do not log me",
        }

    log = AuditLog(tmp_path / "audit.jsonl")
    data = log.record_action(
        event_type="preview",
        action=Action(),
        approval="not_required",
        outcome="previewed",
    )

    assert data["params_summary"] == {"remote_address": "203.0.113.7/32"}
    assert "do not log me" not in (tmp_path / "audit.jsonl").read_text(
        encoding="utf-8"
    )


def test_record_rejects_non_event(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(TypeError):
        log.record({"event_type": "preview"})


def test_read_handles_a_missing_file(tmp_path):
    log = AuditLog(tmp_path / "absent.jsonl")
    assert log.read(10) == []
    assert log.count() == 0
