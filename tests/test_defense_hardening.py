"""Regression tests for the defensive-actions security-hardening pass.

Every Windows, UAC and firewall interaction here is mocked.  No real
``netsh``/``tasklist``/``UAC`` command runs, and the developer's firewall is
never modified.  The tests are grouped by the review findings they cover.

These tests intentionally assert fail-closed behaviour: an ambiguous result is
never reported as success and is never treated as "nothing happened".
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import app as app_module
from defense import policy
from defense.approvals import ActionStore, ApprovalStore, RateLimiter
from defense.audit import AuditLog


DEFENSE_JS = (
    Path(app_module.__file__).resolve().parent
    / "static" / "js" / "defense.js"
)
from defense.models import (
    ActionExpired,
    ActionLimitExceeded,
    ActionRequest,
    ApprovalLimitExceeded,
    AuditEvent,
    DuplicateExecution,
    RateLimited,
    params_hash,
)
from defense.rollback import rollback_for
from defense.service import LIMITATIONS
from defense.windows import elevated, firewall, inspection, security
from defense_support import (
    VALID_BLOCK,
    Clock,
    Completed,
    CsrfClient,
    FakeElevation,
    make_service,
)

CANONICAL = policy.validate_action("create_firewall_block_rule", VALID_BLOCK)
RULE_NAME = policy.rule_name_for(CANONICAL)


# --------------------------------------------------------------- fixtures


@pytest.fixture
def windows(monkeypatch):
    """Simulate Windows and neutralise real ACL syscalls.

    The ACL implementation itself is exercised on a real Windows host in the
    ACL smoke test below.  Here we want deterministic, host-independent logic
    tests, so the DACL apply/verify helpers are mocked.
    """
    monkeypatch.setattr(elevated, "IS_WINDOWS", True)
    monkeypatch.setattr(firewall, "IS_WINDOWS", True)
    monkeypatch.setattr(inspection, "IS_WINDOWS", True)
    monkeypatch.setattr(security, "apply_restricted_acl",
                        lambda *args, **kwargs: True)
    monkeypatch.setattr(security, "acl_is_restricted",
                        lambda *args, **kwargs: True)
    monkeypatch.setattr(security, "acl_is_admin_only",
                        lambda *args, **kwargs: True)
    return monkeypatch


def rule_text(name, params=CANONICAL, override=None):
    """Render verbose ``netsh show rule`` output for the expected parameters."""
    direction = "In" if params["direction"] == "inbound" else "Out"
    protocol = {"tcp": "TCP", "udp": "UDP", "any": "Any"}[params["protocol"]]
    values = {
        "Rule Name": name,
        "Enabled": "Yes",
        "Direction": direction,
        "Profiles": params["profile"],
        "Action": "Block",
        "Protocol": protocol,
        "LocalIP": "Any",
        "RemoteIP": params["remote_address"],
        "LocalPort": params.get("local_port") or "Any",
        "RemotePort": params.get("remote_port") or "Any",
    }
    values.update(override or {})
    return "".join(f"{key}: {value}\n" for key, value in values.items())


class Netsh:
    """Stateful fake for the fixed firewall argv calls; never real."""

    def __init__(self, present=False, override=None,
                 add_failure=None, delete_failure=None, stay_present=False):
        self.present = present
        self.override = override
        self.add_failure = add_failure
        self.delete_failure = delete_failure
        self.stay_present = stay_present
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        name = next(
            (arg[len("name="):] for arg in argv if arg.startswith("name=")),
            RULE_NAME,
        )
        if "show" in argv:
            if self.present:
                return Completed.ok(rule_text(name, override=self.override))
            return Completed.fail(1, "No rules match the specified criteria.")
        if "add" in argv:
            if self.add_failure is not None:
                return self.add_failure
            self.present = True
            return Completed.ok("Ok.")
        if "delete" in argv:
            if self.delete_failure is not None:
                return self.delete_failure
            if not self.stay_present:
                self.present = False
            return Completed.ok("Ok.")
        return Completed.fail(1, "unexpected")

    def count(self, token):
        return sum(token in call for call in self.calls)


def write_request(base, payload, secret=None, name=None):
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


def payload(nonce="a" * 32, action_type="create_firewall_block_rule",
            params=None, issued_at=None, expires_at=None):
    now = time.time()
    return {
        "version": 1,
        "nonce": nonce,
        "action_id": "b" * 32,
        "action_type": action_type,
        "params": CANONICAL if params is None else params,
        "issued_at": now if issued_at is None else issued_at,
        "expires_at": (now + 120) if expires_at is None else expires_at,
    }


# =====================================================================
# F1: helper installation integrity (elevation boundary)
# =====================================================================


def test_helper_installation_requires_the_root_environment(windows, monkeypatch):
    monkeypatch.delenv(elevated.HELPER_ROOT_ENV, raising=False)

    trusted, detail = elevated.verify_helper_installation()

    assert trusted is False
    assert "administrator-protected" in detail


def test_helper_installation_rejects_a_relative_root(windows, monkeypatch,
                                                     tmp_path):
    monkeypatch.setenv(elevated.HELPER_ROOT_ENV, "defense")

    trusted, detail = elevated.verify_helper_installation()

    assert trusted is False
    assert "absolute" in detail


def test_helper_installation_rejects_code_outside_the_root(windows,
                                                           monkeypatch,
                                                           tmp_path):
    monkeypatch.setenv(elevated.HELPER_ROOT_ENV, str(tmp_path))

    trusted, detail = elevated.verify_helper_installation()

    assert trusted is False
    assert "must both live under" in detail


def test_helper_installation_rejects_a_non_admin_only_acl(windows, monkeypatch,
                                                           tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    (root / "elevated.py").write_text("# helper", encoding="utf-8")
    (root / "python.exe").write_text("", encoding="utf-8")
    monkeypatch.setenv(elevated.HELPER_ROOT_ENV, str(root))
    monkeypatch.setattr(elevated, "__file__", str(root / "elevated.py"))
    monkeypatch.setattr(elevated.sys, "executable",
                        str(root / "python.exe"))
    monkeypatch.setattr(security, "acl_is_admin_only",
                        lambda *args, **kwargs: False)

    trusted, detail = elevated.verify_helper_installation()

    assert trusted is False
    assert "writable by a non-administrator" in detail


def test_helper_installation_accepts_a_fully_protected_root(windows,
                                                             monkeypatch,
                                                             tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    (root / "elevated.py").write_text("# helper", encoding="utf-8")
    (root / "python.exe").write_text("", encoding="utf-8")
    monkeypatch.setenv(elevated.HELPER_ROOT_ENV, str(root))
    monkeypatch.setattr(elevated, "__file__", str(root / "elevated.py"))
    monkeypatch.setattr(elevated.sys, "executable",
                        str(root / "python.exe"))

    trusted, detail = elevated.verify_helper_installation()

    assert trusted is True
    assert "administrator-protected" in detail


def test_launch_refuses_an_untrusted_installation(windows, monkeypatch):
    monkeypatch.setattr(elevated, "verify_helper_installation",
                        lambda: (False, "not protected"))

    with pytest.raises(elevated.SecretError) as error:
        elevated.launch_elevated(Path("request.json"))

    assert error.value.category == "helper_untrusted"


@pytest.mark.skipif(not security.IS_WINDOWS, reason="Windows-only ctypes")
def test_launch_uses_isolated_mode_and_a_protected_working_directory(
    windows, monkeypatch, tmp_path
):
    root = tmp_path / "install"
    root.mkdir()
    monkeypatch.setenv(elevated.HELPER_ROOT_ENV, str(root))
    monkeypatch.setattr(elevated, "verify_helper_installation",
                        lambda: (True, "ok"))

    calls = []

    class FakeFunction:
        argtypes = None
        restype = None

        def __call__(self, *args):
            calls.append(args)
            return 33

    class FakeShell:
        def __init__(self):
            self.ShellExecuteW = FakeFunction()

    shell = FakeShell()
    monkeypatch.setattr("ctypes.WinDLL", lambda *args, **kwargs: shell)

    code = elevated.launch_elevated(Path("C:/defense/requests/a.json"))

    assert code == 33
    assert len(calls) == 1
    _, verb, executable, arguments, directory, _ = calls[0]
    assert verb == "runas"
    assert executable == str(Path(sys.executable).resolve())
    assert "-I" in arguments
    assert "-m" in arguments
    assert "defense.windows.elevated" in arguments
    assert directory == str(root)


# =====================================================================
# F2: HMAC secret integrity and ACL enforcement
# =====================================================================


@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_secret_of_the_wrong_size_is_rejected(windows, tmp_path, size):
    base = tmp_path / "defense"
    base.mkdir()
    (base / "secret.key").write_bytes(b"k" * size)

    with pytest.raises(elevated.SecretError):
        elevated.load_or_create_secret(base)

    # The invalid key is never regenerated or silently replaced.
    assert (base / "secret.key").read_bytes() == b"k" * size


def test_secret_without_a_verified_acl_is_rejected(windows, tmp_path,
                                                    monkeypatch):
    base = tmp_path / "defense"
    base.mkdir()
    (base / "secret.key").write_bytes(b"k" * 32)
    monkeypatch.setattr(security, "acl_is_restricted",
                        lambda *args, **kwargs: False)

    with pytest.raises(elevated.SecretError) as error:
        elevated.load_or_create_secret(base)

    assert error.value.category == "secret_acl_unverified"


def test_secret_symlink_is_rejected(windows, tmp_path, monkeypatch):
    base = tmp_path / "defense"
    base.mkdir()
    target = base / "secret.key"
    target.write_bytes(b"k" * 32)
    monkeypatch.setattr(security, "is_reparse_point",
                        lambda path: Path(path).name == "secret.key")

    with pytest.raises(elevated.SecretError):
        elevated.load_or_create_secret(base)


def test_new_secret_is_exactly_32_bytes_and_gets_an_acl(windows, tmp_path,
                                                        monkeypatch):
    applied = []
    monkeypatch.setattr(security, "apply_restricted_acl",
                        lambda path, *args, **kwargs: applied.append(path))

    secret = elevated.load_or_create_secret(tmp_path / "defense")

    assert len(secret) == 32
    assert (tmp_path / "defense" / "secret.key").read_bytes() == secret
    assert applied


def test_enabled_adapter_reports_a_bad_secret_instead_of_running(windows,
                                                                  tmp_path,
                                                                  monkeypatch):
    base = tmp_path / "defense"
    base.mkdir()
    (base / "secret.key").write_bytes(b"x")
    launcher_calls = []
    adapter = elevated.ElevationAdapter(
        base_dir=base, enabled=True,
        launcher=lambda path: launcher_calls.append(path) or 33,
        install_verifier=lambda: (True, "test"),
    )

    result = adapter.execute(
        "create_firewall_block_rule", CANONICAL, "a" * 32
    )

    assert result["error_category"] == "secret_wrong_size"
    assert launcher_calls == []


# =====================================================================
# F4: request-file integrity and persistent replay rejection
# =====================================================================


def test_helper_requires_windows(monkeypatch):
    monkeypatch.setattr(elevated, "IS_WINDOWS", False)

    assert elevated.helper_main(["--request", "request.json"]) == 2


def test_helper_rejects_a_request_outside_the_directory(windows, tmp_path):
    outside = tmp_path / ("a" * 32 + ".json")
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError):
        elevated._validate_request_path(outside, tmp_path / "requests")


def test_helper_rejects_a_symlinked_request(windows, tmp_path, monkeypatch):
    directory = tmp_path / "requests"
    directory.mkdir()
    path = directory / ("a" * 32 + ".json")
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    monkeypatch.setattr(security, "is_reparse_point",
                        lambda candidate: True)

    assert elevated.helper_main(["--request", str(path)]) == 2


def test_helper_rejects_an_oversized_request_file(windows, tmp_path,
                                                  monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    directory = tmp_path / "requests"
    directory.mkdir()
    path = directory / ("a" * 32 + ".json")
    path.write_bytes(b"{" + b" " * (elevated.MAX_REQUEST_BYTES + 10) + b"}")

    assert elevated.helper_main(["--request", str(path)]) == 4


def test_helper_rejects_non_finite_json_constants(windows, tmp_path,
                                                  monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    directory = tmp_path / "requests"
    directory.mkdir()
    path = directory / ("a" * 32 + ".json")
    path.write_text(
        '{"payload": {"nonce": "' + "a" * 32 + '", '
        '"issued_at": Infinity}, "signature": "' + "0" * 64 + '"}',
        encoding="utf-8",
    )

    assert elevated.helper_main(["--request", str(path)]) == 4


def test_helper_rejects_a_future_request(windows, tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    now = time.time()
    path = write_request(
        tmp_path,
        payload(issued_at=now + 3600, expires_at=now + 3700),
    )

    assert elevated.helper_main(["--request", str(path)]) == 5

    result = json.loads(
        path.with_name(path.stem + ".result.json").read_text(encoding="utf-8")
    )
    assert result["payload"]["error_category"] == "invalid_request"


def test_helper_rejects_an_overlong_validity_window(windows, tmp_path,
                                                    monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    now = time.time()
    path = write_request(
        tmp_path,
        payload(issued_at=now, expires_at=now + 1000),
    )

    assert elevated.helper_main(["--request", str(path)]) == 5


def test_helper_rejects_a_forged_signature(windows, tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    elevated.load_or_create_secret(tmp_path)
    path = write_request(tmp_path, payload(), secret=b"x" * 32)

    assert elevated.helper_main(["--request", str(path)]) == 4


def test_helper_rejects_a_nonce_mismatch(windows, tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    path = write_request(
        tmp_path, payload(nonce="a" * 32), name="c" * 32
    )

    assert elevated.helper_main(["--request", str(path)]) == 5


def test_helper_consumes_a_request_once_and_rejects_replay(windows, tmp_path,
                                                           monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    calls = []
    monkeypatch.setattr(
        firewall, "create_rule",
        lambda name, params, runner=None: calls.append(name) or {
            "ok": True, "changed": True, "verified": True,
            "already_exists": False, "rule_name": name,
            "error": None, "error_category": None,
        },
    )

    first = write_request(tmp_path, payload())
    assert elevated.helper_main(["--request", str(first)]) == 0
    assert not first.exists()

    # An attacker who restores the exact request file cannot execute it again:
    # the persistent consumed marker is checked before any action runs.
    restored = write_request(tmp_path, payload())
    assert elevated.helper_main(["--request", str(restored)]) == 5
    assert calls == [RULE_NAME]

    result = json.loads(
        restored.with_name(
            restored.stem + ".result.json"
        ).read_text(encoding="utf-8")
    )
    assert result["payload"]["error_category"] == "replay_detected"


def test_helper_revalidates_non_canonical_parameters(windows, tmp_path,
                                                      monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    path = write_request(
        tmp_path, payload(params={"remote_address": "203.0.113.7"})
    )

    assert elevated.helper_main(["--request", str(path)]) == 5


def test_helper_refuses_a_non_elevatable_action(windows, tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEFENSE_DIR", str(tmp_path))
    monkeypatch.setattr(elevated, "is_admin", lambda: True)
    path = write_request(
        tmp_path, payload(action_type="list_processes",
                          params={"limit": 10})
    )

    assert elevated.helper_main(["--request", str(path)]) == 5


# =====================================================================
# F5 / F12: timeout and unverified outcomes are never success
# =====================================================================


def test_adapter_timeout_is_execution_unknown(windows, tmp_path):
    adapter = elevated.ElevationAdapter(
        base_dir=tmp_path, enabled=True,
        launcher=lambda path: 33,
        timeout=0.05, poll=0.01,
        install_verifier=lambda: (True, "test"),
    )

    result = adapter.execute(
        "create_firewall_block_rule", CANONICAL, "a" * 32
    )

    assert result["status"] == "execution_unknown"
    assert result["error_category"] == "execution_unknown"
    assert result["elevation"] == "unknown"
    assert result["detail"]["retry_allowed"] is False


def test_unknown_execution_marks_the_action_and_blocks_retry(tmp_path):
    elevation = FakeElevation(result={
        "status": "execution_unknown",
        "changed": False,
        "verified": False,
        "error": "helper did not answer",
        "error_category": "execution_unknown",
        "elevation": "unknown",
        "detail": {"reason": "helper_still_running"},
    })
    service = make_service(tmp_path, Clock(), elevation=elevation)
    action_id = service.preview(
        "create_firewall_block_rule", VALID_BLOCK
    )["action"]["action_id"]
    token = service.approve(
        action_id, "create_firewall_block_rule"
    )["approval_token"]

    result = service.execute(action_id, token)

    assert result["status"] == "execution_unknown"
    assert service.actions.get_any(action_id).status == "unknown"
    with pytest.raises(DuplicateExecution):
        service.actions.get(action_id)


def test_unverified_execution_claims_no_rollback_or_ownership(tmp_path):
    elevation = FakeElevation(result={
        "status": "unverified",
        "changed": True,
        "verified": False,
        "error": None,
        "error_category": None,
        "elevation": "used",
        "detail": {"rule_name": RULE_NAME},
    })
    service = make_service(tmp_path, Clock(), elevation=elevation)
    action_id = service.preview(
        "create_firewall_block_rule", VALID_BLOCK
    )["action"]["action_id"]
    token = service.approve(
        action_id, "create_firewall_block_rule"
    )["approval_token"]

    result = service.execute(action_id, token)

    assert result["status"] == "unverified"
    assert result["rollback_available"] is False
    assert result["rollback_status"] == "unavailable"
    assert service.rules.list_active() == []


def test_mismatched_helper_rule_name_is_not_recorded(tmp_path):
    elevation = FakeElevation(result={
        "status": "success",
        "changed": True,
        "verified": True,
        "error": None,
        "error_category": None,
        "elevation": "used",
        "detail": {"rule_name": "CyberGuard-Some-Other-Rule"},
    })
    service = make_service(tmp_path, Clock(), elevation=elevation)
    action_id = service.preview(
        "create_firewall_block_rule", VALID_BLOCK
    )["action"]["action_id"]
    token = service.approve(
        action_id, "create_firewall_block_rule"
    )["approval_token"]

    result = service.execute(action_id, token)

    assert result["rollback_available"] is False
    assert result["detail"]["ownership_error"] == "rule_name_mismatch"
    assert service.rules.list_active() == []


# =====================================================================
# F6: firewall query classification and post-change verification
# =====================================================================


def _show(stdout="", stderr="", code=1):
    return lambda argv, **kwargs: Completed(code, stdout, stderr)


def test_query_rule_present_absent_and_failures(windows):
    present = firewall.query_rule(
        RULE_NAME, runner=_show(rule_text(RULE_NAME), "", 0)
    )
    absent = firewall.query_rule(
        RULE_NAME, runner=_show("", "No rules match the specified criteria.", 1)
    )
    denied = firewall.query_rule(
        RULE_NAME,
        runner=_show("", "The requested operation requires elevation.", 1),
    )
    failed = firewall.query_rule(
        RULE_NAME, runner=_show("", "syntax error", 1)
    )
    unsupported = firewall.query_rule(
        RULE_NAME, runner=_show("Localized output only", "", 0)
    )

    assert present["state"] == "present"
    assert absent["state"] == "absent"
    assert denied["state"] == "access_denied"
    assert failed["state"] == "command_failed"
    assert unsupported["state"] == "unsupported_output"


def test_query_rule_reports_a_timeout(windows):
    def timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 1)

    result = firewall.query_rule(RULE_NAME, runner=timeout)

    assert result["state"] == "timeout"


def test_query_rule_rejects_duplicate_rule_output(windows):
    duplicate = rule_text(RULE_NAME) + rule_text(RULE_NAME)

    result = firewall.query_rule(
        RULE_NAME, runner=_show(duplicate, "", 0)
    )

    assert result["state"] == "malformed_output"


def test_rule_exists_raises_instead_of_assuming_absent(windows):
    with pytest.raises(firewall.FirewallCommandError):
        firewall.rule_exists(
            RULE_NAME,
            runner=_show("", "Access is denied.", 1),
        )

    assert firewall.rule_exists(
        RULE_NAME,
        runner=_show("", "No rules match the specified criteria.", 1),
    ) is False


def test_create_rule_verifies_the_exact_properties(windows):
    netsh = Netsh(present=False)

    result = firewall.create_rule(RULE_NAME, CANONICAL, runner=netsh)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["verified"] is True
    assert netsh.count("show") == 2


def test_create_rule_reports_a_conflicting_existing_rule(windows):
    netsh = Netsh(present=True, override={"RemoteIP": "0.0.0.0/0"})

    result = firewall.create_rule(RULE_NAME, CANONICAL, runner=netsh)

    assert result["ok"] is False
    assert result["error_category"] == "rule_conflict"
    assert netsh.count("add") == 0


def test_create_rule_reports_a_post_change_verification_failure(windows):
    class WrongAfterAdd(Netsh):
        def __init__(self):
            super().__init__(
                present=False, override={"RemoteIP": "0.0.0.0/0"}
            )

    netsh = WrongAfterAdd()

    result = firewall.create_rule(RULE_NAME, CANONICAL, runner=netsh)

    assert result["ok"] is False
    assert result["error_category"] == "verification_failed"


def test_create_rule_reports_access_denied(windows):
    netsh = Netsh(
        present=False,
        add_failure=Completed(5, "", "Access is denied."),
    )

    result = firewall.create_rule(RULE_NAME, CANONICAL, runner=netsh)

    assert result["ok"] is False
    assert result["error_category"] == "access_denied"


def test_remove_rule_reports_ownership_mismatch_and_does_not_delete(windows):
    netsh = Netsh(present=True, override={"RemoteIP": "0.0.0.0/0"})

    result = firewall.remove_rule(
        RULE_NAME, expected_params=CANONICAL, runner=netsh
    )

    assert result["ok"] is False
    assert result["error_category"] == "ownership_mismatch"
    assert netsh.count("delete") == 0


def test_remove_rule_reports_verification_failure(windows):
    netsh = Netsh(present=True, stay_present=True)

    result = firewall.remove_rule(RULE_NAME, runner=netsh)

    assert result["ok"] is False
    assert result["error_category"] == "verification_failed"


# =====================================================================
# F8: independent firewall argument validation
# =====================================================================


def test_build_add_rule_rejects_extra_parameters():
    with pytest.raises(firewall.FirewallCommandError) as error:
        firewall.build_add_rule_argv(
            RULE_NAME, {**CANONICAL, "command": "calc.exe"}
        )

    assert error.value.category == "invalid_parameters"


def test_build_add_rule_rejects_a_mismatched_name():
    with pytest.raises(firewall.FirewallCommandError) as error:
        firewall.build_add_rule_argv(
            "CyberGuard-Not-The-Real-Name", CANONICAL
        )

    assert error.value.category == "not_owned"


@pytest.mark.parametrize("name", ["OtherRule", "", 42, "CyberGuard-bad name"])
def test_remove_rule_rejects_a_non_cyberguard_name(windows, name):
    result = firewall.remove_rule(name, runner=Netsh(present=True))

    assert result["ok"] is False
    assert result["error_category"] == "not_owned"


def test_firewall_refuses_an_untrusted_executable(windows):
    with pytest.raises(firewall.FirewallCommandError) as error:
        firewall._run(["powershell", "-Command", "whoami"])

    assert error.value.category == "untrusted_executable"


def test_inspection_refuses_an_untrusted_executable(windows):
    with pytest.raises(inspection.CommandError) as error:
        inspection._run(["powershell", "-Command", "whoami"])

    assert error.value.category == "untrusted_executable"


@pytest.mark.skipif(not security.IS_WINDOWS, reason="Windows-only path check")
def test_system32_executable_paths_are_absolute():
    for name in ("tasklist.exe", "netstat.exe", "netsh.exe"):
        path = security.trusted_system32_executable(name)
        assert Path(path).is_absolute()
        assert security.is_under_system32(path)


# =====================================================================
# F7: ownership registry validation and rollback ownership
# =====================================================================


def test_registry_is_fail_closed_on_corrupt_json(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text("{not json", encoding="utf-8")
    registry = firewall.RuleRegistry(path)

    with pytest.raises(firewall.RegistryError):
        registry.get_validated(RULE_NAME)
    with pytest.raises(firewall.RegistryError):
        registry.upsert({"rule_name": RULE_NAME, "params": CANONICAL})

    health = registry.health()
    assert health["healthy"] is False
    assert health["corrupt"] is True


def test_registry_rejects_an_unknown_version(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({
        "version": 2, "active": {}, "removed": []
    }), encoding="utf-8")
    registry = firewall.RuleRegistry(path)

    assert registry.get(RULE_NAME) is None
    assert registry.health()["corrupt"] is True


def test_registry_refuses_to_overwrite_malformed_records(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({
        "version": 1,
        "active": {RULE_NAME: {"rule_name": RULE_NAME, "params": {"x": 1}}},
        "removed": [],
    }), encoding="utf-8")
    registry = firewall.RuleRegistry(path)

    with pytest.raises(firewall.RegistryError):
        registry.upsert({"rule_name": RULE_NAME, "params": CANONICAL})


def test_registry_validates_recorded_timestamps(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({
        "version": 1,
        "active": {
            RULE_NAME: {
                "rule_name": RULE_NAME,
                "params": CANONICAL,
                "expires_at": "not-a-number",
            }
        },
        "removed": [],
    }), encoding="utf-8")

    registry = firewall.RuleRegistry(path)

    assert registry.get(RULE_NAME) is None
    assert registry.health()["invalid_entries"] == 1


class FakeRules:
    def __init__(self, record=None, removed=None, error=None):
        self.record = record
        self.removed = removed or []
        self.error = error

    def assert_owned(self, rule_name):
        if self.error is not None:
            raise self.error
        return self.record

    def list_removed(self):
        return self.removed


def create_action(params=None):
    return SimpleNamespace(
        action_id="a" * 32,
        action_type="create_firewall_block_rule",
        params=params or CANONICAL,
    )


def test_rollback_requires_a_non_corrupt_registry():
    rules = FakeRules(
        error=firewall.RegistryError("corrupt")
    )

    with pytest.raises(Exception) as error:
        rollback_for(create_action(), rules)

    assert getattr(error.value, "error_category", "") == "rollback_unavailable"


def test_rollback_requires_an_active_owned_record():
    with pytest.raises(Exception) as error:
        rollback_for(create_action(), FakeRules(record=None))

    assert error.value.error_category == "rollback_unavailable"


def test_rollback_rejects_a_record_created_by_another_action():
    record = {
        "rule_name": RULE_NAME,
        "action_id": "c" * 32,
        "params": CANONICAL,
    }

    with pytest.raises(Exception) as error:
        rollback_for(create_action(), FakeRules(record=record))

    assert error.value.error_category == "rollback_not_owned"


def test_rollback_rejects_mismatched_recorded_parameters():
    other = policy.validate_action(
        "create_firewall_block_rule",
        {**VALID_BLOCK, "local_port": 2222},
    )
    record = {
        "rule_name": RULE_NAME,
        "action_id": "a" * 32,
        "params": other,
    }

    with pytest.raises(Exception) as error:
        rollback_for(create_action(), FakeRules(record=record))

    assert error.value.error_category == "rollback_not_owned"


def test_rollback_of_a_removal_recreates_the_exact_rule():
    action = SimpleNamespace(
        action_id="d" * 32,
        action_type="remove_cyberguard_firewall_rule",
        params={"rule_name": RULE_NAME},
    )
    rules = FakeRules(removed=[{
        "rule_name": RULE_NAME,
        "removed_by_action_id": action.action_id,
        "params": CANONICAL,
    }])

    action_type, params = rollback_for(action, rules)

    assert action_type == "create_firewall_block_rule"
    assert params == CANONICAL


def test_rollback_of_a_removal_requires_a_matching_record():
    action = SimpleNamespace(
        action_id="d" * 32,
        action_type="remove_cyberguard_firewall_rule",
        params={"rule_name": RULE_NAME},
    )

    with pytest.raises(Exception) as error:
        rollback_for(action, FakeRules(removed=[]))

    assert error.value.error_category == "rollback_not_owned"


# =====================================================================
# F9: bounded stores and rate limiting
# =====================================================================


def make_action(action_id="a" * 32, now=1_700_000_000.0):
    return ActionRequest(
        action_id=action_id,
        action_type="create_firewall_block_rule",
        params={"remote_address": "203.0.113.7/32"},
        target="Windows Firewall",
        risk="medium",
        requires_admin=True,
        rollback_supported=True,
        created_at=now,
        expires_at=now + 900,
        params_hash=params_hash({"remote_address": "203.0.113.7/32"}),
    )


def test_action_store_enforces_a_capacity_limit():
    store = ActionStore(clock=Clock(), max_items=2)
    store.add(make_action("a" * 32))
    store.add(make_action("b" * 32))

    with pytest.raises(ActionLimitExceeded):
        store.add(make_action("c" * 32))


def test_action_store_prunes_finished_actions_before_refusing():
    clock = Clock()
    store = ActionStore(clock=clock, max_items=2)
    store.add(make_action("a" * 32))
    store.add(make_action("b" * 32))
    store.claim("a" * 32)
    store.finish("a" * 32)

    stored = store.add(make_action("c" * 32))

    assert stored.action_id == "c" * 32


def test_approval_store_enforces_a_capacity_limit():
    store = ApprovalStore(clock=Clock(), max_items=1)
    store.issue(make_action("a" * 32))

    with pytest.raises(ApprovalLimitExceeded):
        store.issue(make_action("b" * 32))


def test_rate_limiter_is_a_sliding_window():
    clock = Clock()
    limiter = RateLimiter(clock=clock, limit=2, window=60)

    assert limiter.allow("preview") is True
    assert limiter.allow("preview") is True
    assert limiter.allow("preview") is False

    clock.advance(61)

    assert limiter.allow("preview") is True


def test_service_rate_limits_repeated_previews(tmp_path):
    service = make_service(tmp_path, Clock())

    with pytest.raises(RateLimited):
        for _ in range(200):
            service.preview("create_firewall_block_rule", VALID_BLOCK)


# =====================================================================
# F10: audit-log integrity, bounded rotation and honest limits
# =====================================================================


def test_audit_rotation_keeps_history_bounded(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, max_bytes=1)

    for outcome in ("first", "second"):
        log.record(AuditEvent(
            event_type="execution",
            action_id="a" * 32,
            action_type="create_firewall_block_rule",
            target="Windows Firewall",
            params_summary={},
            approval="granted",
            outcome=outcome,
            error_category=None,
            elevation="used",
            rollback_available=False,
            rollback_status="not_applicable",
            timestamp=1_700_000_000.0,
        ))

    assert (tmp_path / "audit.jsonl.1").exists()


def test_audit_count_streams_past_the_read_window(tmp_path):
    path = tmp_path / "audit.jsonl"
    line = json.dumps({"event_type": "execution"}) + "\n"
    path.write_text(line * 120_000, encoding="utf-8")
    assert path.stat().st_size > 1024 * 1024

    log = AuditLog(path)

    assert log.count() == 120_000


def test_audit_read_tolerates_malformed_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps({"event_type": "preview"}) + "\n"
        + "this is not json\n"
        + json.dumps({"event_type": "execution"}) + "\n",
        encoding="utf-8",
    )

    events = AuditLog(path).read(10)

    assert [item["event_type"] for item in events] == [
        "execution", "preview"
    ]


def test_audit_refuses_a_symlinked_file(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    log = AuditLog(path)
    monkeypatch.setattr(security, "is_reparse_point",
                        lambda candidate: True)

    with pytest.raises(security.SecurityError):
        log.record(AuditEvent(
            event_type="execution",
            action_id="a" * 32,
            action_type="create_firewall_block_rule",
            target="Windows Firewall",
            params_summary={},
            approval="granted",
            outcome="success",
            error_category=None,
            elevation="used",
            rollback_available=False,
            rollback_status="not_applicable",
            timestamp=1_700_000_000.0,
        ))


def test_limitations_do_not_claim_tamper_proof_audit():
    joined = " ".join(LIMITATIONS).lower()
    assert "append-only" in joined
    assert "same-user" in joined
    assert "tamper" not in joined or "can alter it" in joined
    assert "not proof that the helper stopped" in joined


# =====================================================================
# F3 / F11: API protection, dashboard accuracy and error reporting
# =====================================================================


@pytest.fixture
def api(tmp_path, monkeypatch):
    service = make_service(tmp_path, Clock(), elevation=FakeElevation())
    monkeypatch.setattr(app_module, "defense_service", service)
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield CsrfClient(client), service


def test_status_reports_security_controls(api):
    client, _ = api

    data = client.get("/api/defense/status").get_json()

    assert data["security"] == {
        "loopback_only": True,
        "host_validation": True,
        "origin_validation": True,
        "csrf_required": True,
        "max_body_bytes": 64 * 1024,
    }
    assert data["csrf_token"]
    assert data["audit"]["health"]["path_configured"] is True
    assert data["rules_registry"]["healthy"] is True


def test_dashboard_states_the_lifetime_and_unknown_limitations(api):
    client, _ = api

    html = client.get("/").get_data(as_text=True)
    defense_js = DEFENSE_JS.read_text(encoding="utf-8")

    assert "removed automatically" in html
    # Failure-mode wording is rendered by the extracted defense module.
    assert "Execution outcome unknown" in defense_js
    assert "Known limitations" in html


def test_audit_response_marks_truncation(api):
    client, _ = api
    response = client.get("/api/defense/audit?limit=10")

    assert response.status_code == 200
    body = response.get_json()
    assert body["truncated"] is False
    assert body["count"] >= 0


def test_unknown_outcome_is_surfaced_without_success(api):
    client, service = api
    service.elevation.result = {
        "status": "execution_unknown",
        "changed": False,
        "verified": False,
        "error": "timeout",
        "error_category": "execution_unknown",
        "elevation": "unknown",
        "detail": {"reason": "helper_still_running"},
    }
    action_id = client.post(
        "/api/defense/actions/preview",
        json={"action_type": "create_firewall_block_rule",
              "params": VALID_BLOCK},
    ).get_json()["action"]["action_id"]
    token = client.post(
        f"/api/defense/actions/{action_id}/approve",
        json={"confirm": "create_firewall_block_rule"},
    ).get_json()["approval_token"]

    body = client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={"approval_token": token},
    ).get_json()

    assert body["status"] == "execution_unknown"
    assert body["changed"] is False
    assert body["rollback_available"] is False


def test_tampered_admin_boolean_and_parameters_are_ignored(api):
    client, service = api
    action_id = client.post(
        "/api/defense/actions/preview",
        json={"action_type": "create_firewall_block_rule",
              "params": VALID_BLOCK},
    ).get_json()["action"]["action_id"]
    token = client.post(
        f"/api/defense/actions/{action_id}/approve",
        json={"confirm": "create_firewall_block_rule"},
    ).get_json()["approval_token"]

    body = client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={
            "approval_token": token,
            "approved": True,
            "action_type": "remove_cyberguard_firewall_rule",
            "params": {"remote_address": "198.51.100.9"},
        },
    ).get_json()

    assert body["status"] == "success"
    assert service.rules.list_active()[0]["params"][
        "remote_address"
    ] == "203.0.113.7/32"
