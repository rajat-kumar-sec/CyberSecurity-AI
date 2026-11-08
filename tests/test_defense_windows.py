"""Windows layer tests: inspection parsing, firewall argv, UAC hand-off.

Every command is mocked. No real ``tasklist``, ``netsh`` or UAC prompt runs and
the developer's firewall is never modified.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from defense import policy
from defense.models import UnknownActionError
from defense.windows import elevated, firewall, inspection
from defense_support import (
    FIREWALL_TEXT,
    NETSTAT_TEXT,
    TASKLIST_CSV,
    Clock,
    Completed,
    RecordingRunner,
    VALID_BLOCK,
)

CANONICAL = policy.validate_action("create_firewall_block_rule", VALID_BLOCK)
RULE_NAME = policy.rule_name_for(CANONICAL)


def trusted_install():
    """Pretend the helper installation is administrator-protected."""
    return True, "test install"


# ------------------------------------------------------------- inspection


def test_parse_tasklist_reads_csv_rows():
    rows, truncated = inspection.parse_tasklist(TASKLIST_CSV, 10)

    assert truncated is False
    assert rows == [
        {
            "name": "chrome.exe",
            "pid": 1234,
            "session": "Console",
            "session_number": "1",
            "memory": "100,000 K",
        },
        {
            "name": "python.exe",
            "pid": 5678,
            "session": "Console",
            "session_number": "1",
            "memory": "80,000 K",
        },
    ]


def test_parse_tasklist_honours_the_limit():
    rows, truncated = inspection.parse_tasklist(TASKLIST_CSV, 1)

    assert len(rows) == 1
    assert truncated is True


def test_parse_tasklist_skips_malformed_rows():
    rows, _ = inspection.parse_tasklist(
        '"good.exe","42","Console","1","10 K"\nnot,csv\n', 10
    )

    assert len(rows) == 1
    assert rows[0]["pid"] == 42


def test_parse_netstat_reads_tcp_and_udp():
    rows, truncated = inspection.parse_netstat(NETSTAT_TEXT, 10)

    assert truncated is False
    assert len(rows) == 3
    assert rows[0]["protocol"] == "TCP"
    assert rows[0]["state"] == "LISTENING"
    assert rows[0]["pid"] == 1234
    assert rows[2]["protocol"] == "UDP"
    assert rows[2]["state"] == "-"


def test_parse_netstat_filters_by_protocol_and_limit():
    tcp, _ = inspection.parse_netstat(NETSTAT_TEXT, 10, protocol="tcp")
    udp, _ = inspection.parse_netstat(NETSTAT_TEXT, 10, protocol="udp")
    limited, truncated = inspection.parse_netstat(NETSTAT_TEXT, 1)

    assert len(tcp) == 2
    assert len(udp) == 1
    assert len(limited) == 1
    assert truncated is True


def test_parse_firewall_state_reads_all_profiles():
    profiles, parsed = inspection.parse_firewall_state(FIREWALL_TEXT)

    assert parsed is True
    assert profiles == [
        {"profile": "domain", "enabled": True},
        {"profile": "private", "enabled": False},
        {"profile": "public", "enabled": True},
    ]


def test_parse_firewall_state_reports_unparsable_output():
    profiles, parsed = inspection.parse_firewall_state("something else")

    assert parsed is False
    assert profiles == []


def test_list_processes_uses_a_fixed_command(monkeypatch):
    monkeypatch.setattr(inspection, "IS_WINDOWS", True)
    runner = RecordingRunner(default=Completed.ok(TASKLIST_CSV))

    result = inspection.run_inspection(
        "list_processes", {"limit": 5}, runner=runner
    )

    assert result["available"] is True
    assert result["state_changed"] is False
    assert result["count"] == 2
    assert runner.calls == [[inspection.TASKLIST, "/FO", "CSV", "/NH"]]


def test_list_network_connections_uses_netstat(monkeypatch):
    monkeypatch.setattr(inspection, "IS_WINDOWS", True)
    runner = RecordingRunner(default=Completed.ok(NETSTAT_TEXT))

    result = inspection.run_inspection(
        "list_network_connections", {"limit": 10, "protocol": "all"},
        runner=runner,
    )

    assert result["available"] is True
    assert result["count"] == 3
    assert runner.calls == [[inspection.NETSTAT, "-ano"]]


def test_get_firewall_status_can_hide_raw_text(monkeypatch):
    monkeypatch.setattr(inspection, "IS_WINDOWS", True)
    runner = RecordingRunner(default=Completed.ok(FIREWALL_TEXT))

    shown = inspection.run_inspection(
        "get_firewall_status", {"include_raw": True}, runner=runner
    )
    hidden = inspection.run_inspection(
        "get_firewall_status", {"include_raw": False}, runner=runner
    )

    assert shown["raw"]
    assert hidden["raw"] is None
    assert runner.calls[0] == [
        inspection.NETSH, "advfirewall", "show", "allprofiles", "state"
    ]


def test_non_windows_returns_a_safe_unavailable_result(monkeypatch):
    monkeypatch.setattr(inspection, "IS_WINDOWS", False)

    result = inspection.run_inspection("list_processes", {"limit": 10})

    assert result["available"] is False
    assert result["error_category"] == "unsupported_os"


def test_command_timeout_is_reported(monkeypatch):
    monkeypatch.setattr(inspection, "IS_WINDOWS", True)

    def timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 1)

    result = inspection.run_inspection(
        "list_processes", {"limit": 10}, runner=timeout
    )

    assert result["available"] is False
    assert result["error_category"] == "timeout"


def test_missing_command_is_reported(monkeypatch):
    monkeypatch.setattr(inspection, "IS_WINDOWS", True)

    def missing(argv, **kwargs):
        raise FileNotFoundError("not found")

    result = inspection.run_inspection(
        "list_processes", {"limit": 10}, runner=missing
    )

    assert result["error_category"] == "command_not_found"


def test_non_zero_exit_is_reported(monkeypatch):
    monkeypatch.setattr(inspection, "IS_WINDOWS", True)
    runner = RecordingRunner(default=Completed.fail(1, "access denied"))

    result = inspection.run_inspection(
        "get_firewall_status", {"include_raw": True}, runner=runner
    )

    assert result["available"] is False
    assert result["error_category"] == "command_failed"


def test_unknown_inspection_is_rejected():
    with pytest.raises(UnknownActionError):
        inspection.run_inspection("create_firewall_block_rule", {})


# --------------------------------------------------------------- firewall


def test_build_add_rule_argv_is_a_fixed_list():
    argv = firewall.build_add_rule_argv(RULE_NAME, CANONICAL)

    assert argv[:5] == [
        firewall.NETSH, "advfirewall", "firewall", "add", "rule"
    ]
    assert f"name={RULE_NAME}" in argv
    assert "dir=in" in argv
    assert "action=block" in argv
    assert "protocol=TCP" in argv
    assert "remoteip=203.0.113.7/32" in argv
    assert "localport=22" in argv
    assert "profile=any" in argv
    assert "enable=yes" in argv


def test_build_add_rule_argv_outbound_uses_dir_out():
    params = policy.validate_action(
        "create_firewall_block_rule",
        {**VALID_BLOCK, "direction": "outbound"},
    )
    argv = firewall.build_add_rule_argv(policy.rule_name_for(params), params)

    assert "dir=out" in argv


@pytest.mark.parametrize(
    "name",
    ["OtherRule", "", "CyberGuard-evil rule", 42],
)
def test_build_add_rule_refuses_unowned_names(name):
    with pytest.raises(firewall.FirewallCommandError) as error:
        firewall.build_add_rule_argv(name, CANONICAL)
    assert error.value.category == "not_owned"


def test_build_add_rule_refuses_a_name_that_does_not_match_params():
    with pytest.raises(firewall.FirewallCommandError):
        firewall.build_add_rule_argv(
            "CyberGuard-Block-In-TCP-0000000000", CANONICAL
        )


def test_show_and_delete_argv():
    assert firewall.build_show_rule_argv(RULE_NAME)[-1] == "verbose"
    assert firewall.build_show_rule_argv(RULE_NAME)[:5] == [
        firewall.NETSH, "advfirewall", "firewall", "show", "rule"
    ]
    assert firewall.build_delete_rule_argv(RULE_NAME)[:5] == [
        firewall.NETSH, "advfirewall", "firewall", "delete", "rule"
    ]


class FakeNetsh:
    """Minimal stateful ``netsh`` stand-in; never touches the real firewall.

    ``show rule ... verbose`` output contains the full property set that
    ``firewall.verify_rule_properties`` checks, so a created rule can only be
    reported as verified when the fake actually reflects the requested
    properties.
    """

    def __init__(self, present=False, add_fails=False, delete_fails=False,
                 params=None):
        self.present = present
        self.add_fails = add_fails
        self.delete_fails = delete_fails
        self.params = params or CANONICAL
        self.calls = []

    def _rule_text(self, name):
        params = self.params
        direction = "In" if params["direction"] == "inbound" else "Out"
        protocol = {
            "tcp": "TCP", "udp": "UDP", "any": "Any"
        }[params["protocol"]]
        return (
            f"Rule Name: {name}\n"
            "Enabled: Yes\n"
            f"Direction: {direction}\n"
            f"Profiles: {params['profile']}\n"
            "Action: Block\n"
            f"Protocol: {protocol}\n"
            "LocalIP: Any\n"
            f"RemoteIP: {params['remote_address']}\n"
            f"LocalPort: {params.get('local_port') or 'Any'}\n"
            f"RemotePort: {params.get('remote_port') or 'Any'}\n"
        )

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        name = next(
            (arg[len("name="):] for arg in argv if arg.startswith("name=")),
            "CyberGuard-unknown",
        )
        if "show" in argv:
            if self.present:
                return Completed.ok(self._rule_text(name))
            return Completed.fail(1, "No rules match the specified criteria.")
        if "add" in argv:
            if self.add_fails:
                return Completed.fail(1, "add failed")
            self.present = True
            return Completed.ok("Ok.")
        if "delete" in argv:
            if self.delete_fails:
                return Completed.fail(1, "delete failed")
            self.present = False
            return Completed.ok("Ok.")
        return Completed.fail(1, "unexpected")


def test_create_rule_is_idempotent_and_verified():
    netsh = FakeNetsh(present=False)

    result = firewall.create_rule(RULE_NAME, CANONICAL, runner=netsh)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["verified"] is True
    assert result["already_exists"] is False
    assert any("add" in call for call in netsh.calls)
    assert sum("show" in call for call in netsh.calls) == 2


def test_create_rule_reuses_an_existing_rule():
    netsh = FakeNetsh(present=True)

    result = firewall.create_rule(RULE_NAME, CANONICAL, runner=netsh)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["already_exists"] is True
    assert not any("add" in call for call in netsh.calls)


def test_create_rule_reports_an_add_failure():
    netsh = FakeNetsh(present=False, add_fails=True)

    result = firewall.create_rule(RULE_NAME, CANONICAL, runner=netsh)

    assert result["ok"] is False
    assert result["changed"] is False
    assert result["error_category"] == "firewall_command_failed"


def test_create_rule_reports_a_verification_failure():
    class NeverPresent(FakeNetsh):
        def __call__(self, argv, **kwargs):
            result = super().__call__(argv, **kwargs)
            self.present = False
            return result

    netsh = NeverPresent(present=False)

    result = firewall.create_rule(RULE_NAME, CANONICAL, runner=netsh)

    assert result["ok"] is False
    assert result["error_category"] == "verification_failed"


def test_remove_rule_refuses_an_unowned_name_without_running_anything():
    netsh = FakeNetsh(present=True)

    result = firewall.remove_rule("SomethingElse", runner=netsh)

    assert result["ok"] is False
    assert result["error_category"] == "not_owned"
    assert netsh.calls == []


def test_remove_rule_deletes_and_verifies_absence():
    netsh = FakeNetsh(present=True)

    result = firewall.remove_rule(RULE_NAME, runner=netsh)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["verified"] is True
    assert any("delete" in call for call in netsh.calls)


def test_remove_rule_is_idempotent_when_already_absent():
    netsh = FakeNetsh(present=False)

    result = firewall.remove_rule(RULE_NAME, runner=netsh)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["already_absent"] is True
    assert not any("delete" in call for call in netsh.calls)


def test_remove_rule_reports_a_delete_failure():
    netsh = FakeNetsh(present=True, delete_fails=True)

    result = firewall.remove_rule(RULE_NAME, runner=netsh)

    assert result["ok"] is False
    assert result["error_category"] == "firewall_command_failed"


# ----------------------------------------------------------- rule registry


def test_rule_registry_records_and_removes_ownership(tmp_path):
    clock = Clock()
    registry = firewall.RuleRegistry(tmp_path / "rules.json", clock=clock)

    registry.upsert({
        "rule_name": RULE_NAME,
        "action_id": "a" * 32,
        "params": CANONICAL,
        "created_at": clock.now,
        "expires_at": clock.now + 60,
    })

    assert registry.is_owned(RULE_NAME)
    assert registry.list_active()[0]["rule_name"] == RULE_NAME
    assert registry.expired() == []

    clock.advance(61)
    assert [item["rule_name"] for item in registry.expired()] == [RULE_NAME]

    removed = registry.mark_removed(RULE_NAME, action_id="b" * 32)
    assert removed["removed_by_action_id"] == "b" * 32
    assert registry.is_owned(RULE_NAME) is False
    assert registry.list_removed()[0]["rule_name"] == RULE_NAME


def test_rule_registry_persists_across_instances(tmp_path):
    path = tmp_path / "rules.json"
    first = firewall.RuleRegistry(path)
    first.upsert({"rule_name": RULE_NAME, "params": CANONICAL})

    second = firewall.RuleRegistry(path)

    assert second.is_owned(RULE_NAME)


def test_rule_registry_refuses_a_non_cyberguard_name(tmp_path):
    registry = firewall.RuleRegistry(tmp_path / "rules.json")

    with pytest.raises(ValueError):
        registry.upsert({"rule_name": "OtherRule"})


# ------------------------------------------------------------- elevation


def test_sign_and_verify_round_trip():
    secret = b"s" * 32
    payload = {"action_id": "a" * 32, "nonce": "n"}
    signature = elevated.sign_payload(payload, secret)

    assert elevated.verify_signed(
        {"payload": payload, "signature": signature}, secret
    )
    assert not elevated.verify_signed(
        {"payload": payload, "signature": signature}, b"x" * 32
    )


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        {"payload": {}, "signature": "not-hex"},
        {"payload": "text", "signature": "abc"},
    ],
)
def test_verify_signed_rejects_malformed_data(data):
    assert elevated.verify_signed(data, b"s" * 32) is False


def test_verify_signed_rejects_a_tampered_payload():
    secret = b"s" * 32
    payload = {"action_id": "a" * 32}
    signature = elevated.sign_payload(payload, secret)
    tampered = {"action_id": "b" * 32}

    assert not elevated.verify_signed(
        {"payload": tampered, "signature": signature}, secret
    )


def test_secret_is_created_once_and_stays_stable(tmp_path):
    first = elevated.load_or_create_secret(tmp_path)
    second = elevated.load_or_create_secret(tmp_path)

    assert len(first) == 32
    assert first == second
    assert (tmp_path / "secret.key").exists()


def test_base_dir_honours_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    assert elevated.defense_base_dir() == tmp_path
    assert elevated.requests_dir() == tmp_path / "requests"


@pytest.mark.parametrize(
    "value, expected",
    [("1", True), ("true", True), ("YES", True), ("on", True),
     ("0", False), ("", False), ("no", False)],
)
def test_elevation_enabled_reads_the_environment(monkeypatch, value, expected):
    monkeypatch.setenv(elevated.ELEVATION_ENV, value)
    assert elevated.elevation_enabled() is expected


def test_adapter_status_is_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    adapter = elevated.ElevationAdapter(base_dir=tmp_path, enabled=False)

    status = adapter.status()

    assert status["supported"] is True
    assert status["enabled"] is False
    assert "CYBERGUARD_DEFENSE_ELEVATION=1" in status["detail"]


def test_adapter_reports_non_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", False)
    adapter = elevated.ElevationAdapter(base_dir=tmp_path, enabled=True)

    assert adapter.status()["supported"] is False
    assert adapter.execute(
        "create_firewall_block_rule", CANONICAL, "a" * 32
    )["error_category"] == "unsupported_os"


def test_adapter_disabled_refuses_to_execute(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    adapter = elevated.ElevationAdapter(
        base_dir=tmp_path, enabled=False, launcher=lambda path: 33
    )

    result = adapter.execute(
        "create_firewall_block_rule", CANONICAL, "a" * 32
    )

    assert result["status"] == "failure"
    assert result["error_category"] == "elevation_disabled"
    assert result["elevation"] == "disabled"


@pytest.mark.parametrize(
    "code, category, elevation_status, status",
    [
        (1223, "uac_cancelled", "cancelled", "cancelled"),
        (5, "uac_denied", "denied", "failure"),
        (2, "launch_failed", "failed", "failure"),
    ],
)
def test_adapter_handles_uac_failures(tmp_path, monkeypatch, code, category,
                                      elevation_status, status):
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    adapter = elevated.ElevationAdapter(
        base_dir=tmp_path, enabled=True, launcher=lambda path: code,
        install_verifier=trusted_install,
    )

    result = adapter.execute(
        "create_firewall_block_rule", CANONICAL, "a" * 32
    )

    assert result["status"] == status
    assert result["error_category"] == category
    assert result["elevation"] == elevation_status
    assert not elevated.requests_dir(tmp_path).exists() or not list(
        elevated.requests_dir(tmp_path).iterdir()
    )


def test_adapter_times_out_waiting_for_the_helper(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    adapter = elevated.ElevationAdapter(
        base_dir=tmp_path,
        enabled=True,
        launcher=lambda path: 33,
        timeout=0.05,
        poll=0.01,
        install_verifier=trusted_install,
    )

    result = adapter.execute(
        "create_firewall_block_rule", CANONICAL, "a" * 32
    )

    assert result["status"] == "execution_unknown"
    assert result["error_category"] == "execution_unknown"
    assert result["elevation"] == "unknown"
    assert result["detail"]["retry_allowed"] is False


def test_adapter_refuses_a_non_elevatable_action(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    adapter = elevated.ElevationAdapter(
        base_dir=tmp_path, enabled=True, launcher=lambda path: 33,
        install_verifier=trusted_install,
    )

    result = adapter.execute("list_processes", {"limit": 10}, "a" * 32)

    assert result["error_category"] == "action_not_elevatable"


def test_adapter_refuses_an_invalid_action_id(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    adapter = elevated.ElevationAdapter(
        base_dir=tmp_path, enabled=True, launcher=lambda path: 33,
        install_verifier=trusted_install,
    )

    result = adapter.execute(
        "create_firewall_block_rule", CANONICAL, "not-an-id"
    )

    assert result["error_category"] == "invalid_parameters"


def test_adapter_accepts_a_signed_helper_result(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)

    def launcher(path):
        request = json.loads(Path(path).read_text(encoding="utf-8"))
        payload = request["payload"]
        secret = elevated.load_or_create_secret(tmp_path)
        result = {
            "nonce": payload["nonce"],
            "action_id": payload["action_id"],
            "status": "success",
            "changed": True,
            "verified": True,
            "error": None,
            "error_category": None,
            "detail": {"rule_name": RULE_NAME},
        }
        signed = {
            "payload": result,
            "signature": elevated.sign_payload(result, secret),
        }
        Path(path).with_name(
            Path(path).stem + ".result.json"
        ).write_text(json.dumps(signed), encoding="utf-8")
        return 33

    adapter = elevated.ElevationAdapter(
        base_dir=tmp_path, enabled=True, launcher=launcher,
        timeout=2.0, poll=0.01, install_verifier=trusted_install,
    )

    result = adapter.execute(
        "create_firewall_block_rule", CANONICAL, "a" * 32
    )

    assert result["status"] == "success"
    assert result["changed"] is True
    assert result["elevation"] == "used"


def test_adapter_rejects_a_tampered_helper_result(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)

    def launcher(path):
        request = json.loads(Path(path).read_text(encoding="utf-8"))
        payload = request["payload"]
        result = {
            "nonce": payload["nonce"],
            "action_id": payload["action_id"],
            "status": "success",
            "changed": True,
            "verified": True,
        }
        signed = {
            "payload": result,
            "signature": elevated.sign_payload(result, b"x" * 32),
        }
        Path(path).with_name(
            Path(path).stem + ".result.json"
        ).write_text(json.dumps(signed), encoding="utf-8")
        return 33

    adapter = elevated.ElevationAdapter(
        base_dir=tmp_path, enabled=True, launcher=launcher,
        timeout=2.0, poll=0.01, install_verifier=trusted_install,
    )

    result = adapter.execute(
        "create_firewall_block_rule", CANONICAL, "a" * 32
    )

    assert result["error_category"] == "invalid_result_signature"


def test_adapter_rejects_a_result_for_another_request(tmp_path, monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)

    def launcher(path):
        request = json.loads(Path(path).read_text(encoding="utf-8"))
        payload = request["payload"]
        secret = elevated.load_or_create_secret(tmp_path)
        result = {
            "nonce": "c" * 32,
            "action_id": payload["action_id"],
            "status": "success",
            "changed": True,
            "verified": True,
        }
        signed = {
            "payload": result,
            "signature": elevated.sign_payload(result, secret),
        }
        Path(path).with_name(
            Path(path).stem + ".result.json"
        ).write_text(json.dumps(signed), encoding="utf-8")
        return 33

    adapter = elevated.ElevationAdapter(
        base_dir=tmp_path, enabled=True, launcher=launcher,
        timeout=2.0, poll=0.01, install_verifier=trusted_install,
    )

    result = adapter.execute(
        "create_firewall_block_rule", CANONICAL, "a" * 32
    )

    assert result["error_category"] == "result_mismatch"


# ---------------------------------------------------------------- helper


def _write_request(base, payload, secret=None, name=None):
    secret = secret or elevated.load_or_create_secret(base)
    directory = elevated.requests_dir(base)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name or payload['nonce']}.json"
    signed = {
        "payload": payload,
        "signature": elevated.sign_payload(payload, secret),
    }
    path.write_text(json.dumps(signed), encoding="utf-8")
    return path


def _payload(action_type="create_firewall_block_rule", nonce="a" * 32,
             params=None, issued_at=None, expires_at=None):
    import time

    now = time.time()
    return {
        "version": 1,
        "nonce": nonce,
        "action_id": "b" * 32,
        "action_type": action_type,
        "params": params if params is not None else CANONICAL,
        "issued_at": now if issued_at is None else issued_at,
        "expires_at": (now + 120) if expires_at is None else expires_at,
    }


def test_helper_rejects_a_request_outside_the_request_directory(tmp_path):
    outside = tmp_path / ("a" * 32 + ".json")
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError):
        elevated._validate_request_path(outside, tmp_path / "requests")


def test_helper_rejects_a_bad_request_file_name(tmp_path):
    directory = tmp_path / "requests"
    directory.mkdir()
    bad = directory / "not-a-nonce.json"

    with pytest.raises(ValueError):
        elevated._validate_request_path(bad, directory)


def test_helper_requires_windows(monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", False)
    assert elevated.helper_main(["--request", "anything.json"]) == 2


def test_helper_requires_administrator_privileges(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(elevated, "is_admin", lambda: False)
    path = _write_request(tmp_path, _payload())

    assert elevated.helper_main(["--request", str(path)]) == 3


def test_helper_rejects_a_forged_signature(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    base = tmp_path
    elevated.load_or_create_secret(base)
    path = _write_request(base, _payload(), secret=b"x" * 32)

    assert elevated.helper_main(["--request", str(path)]) == 4


def test_helper_rejects_an_expired_request(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    base = tmp_path
    payload = _payload(issued_at=1.0, expires_at=2.0)
    path = _write_request(base, payload)

    assert elevated.helper_main(["--request", str(path)]) == 5

    result_path = path.with_name(path.stem + ".result.json")
    signed = json.loads(result_path.read_text(encoding="utf-8"))
    secret = elevated.load_or_create_secret(base)
    assert elevated.verify_signed(signed, secret)
    assert signed["payload"]["error_category"] == "request_expired"


def test_helper_rejects_a_nonce_mismatch(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    base = tmp_path
    path = _write_request(base, _payload(nonce="a" * 32), name="c" * 32)

    assert elevated.helper_main(["--request", str(path)]) == 5


def test_helper_executes_a_signed_request_once(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(elevated, "is_admin", lambda: True)

    calls = []

    def fake_create(rule_name, params, runner=None):
        calls.append((rule_name, params))
        return {
            "ok": True,
            "changed": True,
            "verified": True,
            "already_exists": False,
            "rule_name": rule_name,
            "error": None,
            "error_category": None,
        }

    monkeypatch.setattr(firewall, "create_rule", fake_create)

    base = tmp_path
    payload = _payload()
    path = _write_request(base, payload)

    assert elevated.helper_main(["--request", str(path)]) == 0
    assert len(calls) == 1
    assert calls[0][0] == RULE_NAME

    result_path = path.with_name(path.stem + ".result.json")
    signed = json.loads(result_path.read_text(encoding="utf-8"))
    secret = elevated.load_or_create_secret(base)
    assert elevated.verify_signed(signed, secret)
    assert signed["payload"]["status"] == "success"
    assert signed["payload"]["nonce"] == payload["nonce"]
    assert signed["payload"]["action_id"] == payload["action_id"]

    # The request file was consumed: a replay cannot read it again.
    assert not path.exists()
    assert elevated.helper_main(["--request", str(path)]) == 4


def test_helper_removes_a_recorded_cyberguard_rule(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(elevated, "is_admin", lambda: True)

    registry = firewall.RuleRegistry(tmp_path / "rules.json")
    registry.upsert({
        "rule_name": RULE_NAME,
        "params": CANONICAL,
        "action_id": "b" * 32,
    })

    calls = []

    def fake_remove(rule_name, expected_params=None, runner=None):
        calls.append((rule_name, expected_params))
        return {
            "ok": True,
            "changed": True,
            "verified": True,
            "already_absent": False,
            "rule_name": rule_name,
            "error": None,
            "error_category": None,
        }

    monkeypatch.setattr(firewall, "remove_rule", fake_remove)

    payload = _payload(
        action_type="remove_cyberguard_firewall_rule",
        params={"rule_name": RULE_NAME},
    )
    path = _write_request(tmp_path, payload)

    assert elevated.helper_main(["--request", str(path)]) == 0
    assert calls == [(RULE_NAME, CANONICAL)]

    result_path = path.with_name(path.stem + ".result.json")
    signed = json.loads(result_path.read_text(encoding="utf-8"))
    assert elevated.verify_signed(
        signed, elevated.load_or_create_secret(tmp_path)
    )
    assert signed["payload"]["status"] == "success"


def test_helper_refuses_to_remove_an_unrecorded_rule(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(elevated, "is_admin", lambda: True)

    def forbidden(rule_name, runner=None):
        raise AssertionError("remove_rule must not be called")

    monkeypatch.setattr(firewall, "remove_rule", forbidden)

    payload = _payload(
        action_type="remove_cyberguard_firewall_rule",
        params={"rule_name": RULE_NAME},
    )
    path = _write_request(tmp_path, payload)

    assert elevated.helper_main(["--request", str(path)]) == 5

    result_path = path.with_name(path.stem + ".result.json")
    signed = json.loads(result_path.read_text(encoding="utf-8"))
    assert signed["payload"]["error_category"] == "not_owned"


def test_helper_revalidates_non_canonical_parameters(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    base = tmp_path
    payload = _payload(params={"remote_address": "203.0.113.7"})
    path = _write_request(base, payload)

    assert elevated.helper_main(["--request", str(path)]) == 5

    result_path = path.with_name(path.stem + ".result.json")
    signed = json.loads(result_path.read_text(encoding="utf-8"))
    assert signed["payload"]["error_category"] == "invalid_parameters"


def test_helper_refuses_a_non_elevatable_action(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    base = tmp_path
    payload = _payload(action_type="list_processes", params={"limit": 10})
    path = _write_request(base, payload)

    assert elevated.helper_main(["--request", str(path)]) == 5

    result_path = path.with_name(path.stem + ".result.json")
    signed = json.loads(result_path.read_text(encoding="utf-8"))
    assert signed["payload"]["error_category"] == "action_not_elevatable"
