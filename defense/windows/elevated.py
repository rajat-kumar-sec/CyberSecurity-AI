"""One-shot Windows UAC hand-off for administrator-only actions.

The Flask process is **never** elevated.  When a state-changing action is
approved, the adapter writes a single signed request file and launches one
short-lived helper with the Windows ``runas`` verb.

Security model (updated hardening pass)
---------------------------------------
* The helper and the Python executable are only accepted from an
  administrator-protected installation root configured with
  ``CYBERGUARD_DEFENSE_HELPER_ROOT``.  A repository-local or user-writable
  checkout is deliberately **not** trusted, so elevation stays disabled unless
  that boundary can be verified.
* The request HMAC key must already exist with exactly 32 bytes and a verified
  restricted Windows ACL.  A missing, empty, short or ACL-unverified key is a
  hard failure; it is never silently regenerated.
* ``os.chmod`` is not used as a security control.  :mod:`defense.windows.security`
  applies and verifies real NTFS DACLs through ``ctypes``.
* Request and result files are read with size, regular-file, hard-link and
  reparse-point checks, and written with unpredictable exclusive temporary
  files.
* A persistent per-nonce consumption marker makes replay across separate
  helper invocations fail even if the request file is restored.
* A timeout is reported as ``execution_unknown``; it is never converted into
  success or a definitive failure.

Honest limitation
-----------------
The data directory is owned by the interactive user.  A same-user process can
still read or modify it, and can therefore forge requests if it obtains the
key.  This design is not a protection boundary against malware running as the
same Windows account.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path

from defense import policy
from defense.models import canonical_json
from defense.windows import firewall
from defense.windows import security

IS_WINDOWS = sys.platform == "win32"

ELEVATION_ENV = "CYBERGUARD_DEFENSE_ELEVATION"
HELPER_ROOT_ENV = "CYBERGUARD_DEFENSE_HELPER_ROOT"
ELEVATED_ACTIONS = (
    "create_firewall_block_rule",
    "remove_cyberguard_firewall_rule",
)

DEFAULT_TIMEOUT = 180
DEFAULT_POLL_SECONDS = 0.25
REQUEST_TTL_SECONDS = 120
MAX_CLOCK_SKEW_SECONDS = 60
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESULT_BYTES = 64 * 1024
SECRET_BYTES = 32
CONSUMED_RETENTION_SECONDS = REQUEST_TTL_SECONDS + (2 * MAX_CLOCK_SKEW_SECONDS)

ERROR_ACCESS_DENIED = 5
ERROR_CANCELLED = 1223

_REQUEST_NAME_RE = re.compile(r"^[a-f0-9]{32}\.json$")
_ACTION_ID_RE = re.compile(r"^[a-f0-9]{32}$")
_NONCE_RE = re.compile(r"^[a-f0-9]{32}$")


class SecretError(Exception):
    """The HMAC key is missing, malformed or not ACL-protected."""

    def __init__(self, message, category="secret_integrity_failed"):
        super().__init__(message)
        self.message = str(message)
        self.category = category


class RequestError(Exception):
    """A request or result file failed a strict integrity check."""

    def __init__(self, message, category="invalid_request"):
        super().__init__(message)
        self.message = str(message)
        self.category = category


class ReplayDetected(RequestError):
    def __init__(self, message="This request was already consumed."):
        super().__init__(message, "replay_detected")


def defense_base_dir():
    """Where audit, rules and one-time requests live (git-ignored)."""
    raw = os.environ.get("CYBERGUARD_DEFENSE_DIR")
    if raw:
        return Path(raw)
    return Path(__file__).resolve().parents[2] / "data" / "defense"


def requests_dir(base_dir=None):
    return Path(base_dir or defense_base_dir()) / "requests"


def consumed_dir(base_dir=None):
    return Path(base_dir or defense_base_dir()) / "consumed"


def elevation_enabled():
    value = os.environ.get(ELEVATION_ENV, "")
    return value.strip().lower() in ("1", "true", "yes", "on")


def is_admin():
    """True only when the current process is actually elevated."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _secret_path(base_dir):
    return Path(base_dir) / "secret.key"


def _validate_secret_bytes(data):
    if not isinstance(data, (bytes, bytearray)):
        raise SecretError("The HMAC key is not binary data.")
    if len(data) != SECRET_BYTES:
        raise SecretError(
            f"The HMAC key must be exactly {SECRET_BYTES} bytes; "
            f"found {len(data)}.",
            "secret_wrong_size",
        )
    if not any(data):
        raise SecretError("The HMAC key is empty.", "secret_empty")


def _read_existing_secret(path):
    try:
        data = security.secure_read(path, SECRET_BYTES)
    except security.SecurityError as exc:
        raise SecretError(
            f"The HMAC key failed an integrity check: {exc.message}",
            exc.category if exc.category != "security_error"
            else "secret_integrity_failed",
        ) from None
    _validate_secret_bytes(data)
    if IS_WINDOWS and not security.acl_is_restricted(path):
        raise SecretError(
            "The HMAC key does not have a verified restricted Windows ACL.",
            "secret_acl_unverified",
        )
    return data


def load_or_create_secret(base_dir=None):
    """Load the exactly-32-byte HMAC key or create it once, atomically.

    Existing empty, short, oversized, reparse-point or ACL-unverified key files
    are rejected.  They are never overwritten, because doing so could make
    already-signed requests ambiguous.
    """
    base = Path(base_dir or defense_base_dir())
    path = _secret_path(base)

    if path.exists() or path.is_symlink():
        return _read_existing_secret(path)

    try:
        if IS_WINDOWS:
            security.secure_mkdir(base, restricted=True)
        else:
            security.secure_mkdir(base)
    except security.SecurityError as exc:
        raise SecretError(
            f"The key directory is not safe: {exc.message}",
            "secret_acl_unverified",
        ) from None

    candidate = secrets.token_bytes(SECRET_BYTES)
    descriptor = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(candidate)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass

        if IS_WINDOWS:
            security.apply_restricted_acl(path)
            if not security.acl_is_restricted(path):
                raise SecretError(
                    "The new HMAC key ACL could not be verified.",
                    "secret_acl_unverified",
                )
    except FileExistsError:
        # Another process won the creation race; validate its file instead of
        # replacing it.
        return _read_existing_secret(path)
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return candidate


def sign_payload(payload, secret):
    return hmac.new(
        secret,
        canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_signed(data, secret):
    if not isinstance(data, dict):
        return False
    payload = data.get("payload")
    signature = data.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False
    if len(signature) != 64:
        return False
    try:
        expected = sign_payload(payload, secret)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, signature)


def _atomic_write_json(path, data):
    """Write JSON atomically with a random temp name and an ACL-checked file."""
    path = Path(path)
    text = json.dumps(
        data,
        ensure_ascii=True,
        sort_keys=True,
        allow_nan=False,
    )
    security.secure_atomic_write(
        path,
        text.encode("utf-8"),
        mode=0o600,
        restricted=IS_WINDOWS,
    )
    return path


def _result_path(request_path):
    return Path(request_path).with_name(
        Path(request_path).stem + ".result.json"
    )


def _running_path(request_path):
    return Path(request_path).with_name(
        Path(request_path).stem + ".running"
    )


def _consumed_marker(base_dir, nonce):
    return consumed_dir(base_dir) / f"{nonce}.used"


def _prune_consumed(base_dir, clock=time.time):
    directory = consumed_dir(base_dir)
    if not directory.exists():
        return
    cutoff = float(clock()) - CONSUMED_RETENTION_SECONDS
    try:
        entries = list(directory.iterdir())
    except OSError:
        return
    for entry in entries[:1000]:
        try:
            if entry.is_file() and entry.stat().st_mtime < cutoff:
                entry.unlink(missing_ok=True)
        except OSError:
            continue


def _mark_consumed(base_dir, nonce):
    directory = consumed_dir(base_dir)
    security.secure_mkdir(directory, restricted=IS_WINDOWS)
    marker = _consumed_marker(base_dir, nonce)
    descriptor = None
    try:
        descriptor = os.open(
            marker,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(nonce.encode("ascii"))
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        return True
    except FileExistsError:
        raise ReplayDetected() from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _reject_json_constant(value):
    raise ValueError(f"Non-finite JSON number is not allowed: {value!r}")


def _load_json_file(path, max_bytes, category="invalid_request"):
    try:
        raw = security.secure_read(path, max_bytes)
        text = raw.decode("utf-8")
        data = json.loads(text, parse_constant=_reject_json_constant)
    except security.SecurityError as exc:
        raise RequestError(exc.message, exc.category) from None
    except (UnicodeDecodeError, ValueError) as exc:
        raise RequestError(
            f"The JSON file is malformed ({type(exc).__name__}).", category
        ) from None
    if not isinstance(data, dict):
        raise RequestError("The JSON file must contain an object.", category)
    return data


def verify_helper_installation():
    """Verify a genuinely administrator-protected helper installation.

    Returns ``(trusted, detail)``.  This is intentionally strict: an ordinary
    repository checkout, a user-writable virtual environment or a bare
    absolute path is **not** enough to make code safe to run as administrator.
    """
    if not IS_WINDOWS:
        return False, "Elevation is only available on Windows."
    raw = os.environ.get(HELPER_ROOT_ENV, "").strip()
    if not raw:
        return (
            False,
            f"Set {HELPER_ROOT_ENV} to an administrator-protected installation "
            "root; the repository checkout is not trusted.",
        )

    root = Path(raw)
    try:
        if not root.is_absolute():
            return False, "The helper installation root must be absolute."
        security.assert_safe_path(root, kind="dir")
        module_path = Path(__file__).resolve()
        executable = Path(sys.executable).resolve()
        module_path.relative_to(root.resolve())
        executable.relative_to(root.resolve())
    except (OSError, ValueError, security.SecurityError):
        return (
            False,
            "The helper module and Python executable must both live under "
            f"{HELPER_ROOT_ENV}.",
        )

    for path in (root, module_path, executable):
        if security.is_reparse_point(path):
            return False, "A helper path is a symlink, junction or reparse point."
        if not security.acl_is_admin_only(path):
            return (
                False,
                "The helper root, executable or module is writable by a "
                "non-administrator principal.",
            )
    return True, "Helper installation is administrator-protected."


def launch_elevated(request_path):
    """Ask Windows for UAC elevation for the fixed helper command.

    The helper is launched with ``-I`` (isolated Python: no user site, no
    ``PYTHONPATH``, no script-directory injection), an absolute interpreter and
    a protected working directory.  Returns the ``ShellExecuteW`` code:
    ``<= 32`` means failure, with 5 for access denied and 1223 for a cancelled
    prompt.
    """
    import ctypes
    from ctypes import wintypes

    trusted, detail = verify_helper_installation()
    if not trusted:
        raise SecretError(detail, "helper_untrusted")

    root = Path(os.environ[HELPER_ROOT_ENV]).resolve()
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteW.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]
    shell32.ShellExecuteW.restype = ctypes.c_void_p

    arguments = subprocess.list2cmdline([
        "-I",
        "-m",
        "defense.windows.elevated",
        "--request",
        str(request_path),
    ])

    handle = shell32.ShellExecuteW(
        None,
        "runas",
        str(Path(sys.executable).resolve()),
        arguments,
        str(root),
        0,  # SW_HIDE: UAC prompts, but no visible helper console
    )
    return int(handle or 0)


def _failure(error, category, elevation="failed", status="failure", detail=None):
    return {
        "status": status,
        "changed": False,
        "verified": False,
        "error": error,
        "error_category": category,
        "elevation": elevation,
        "detail": dict(detail or {}),
    }


def _unknown_result(reason, observed=None):
    return _failure(
        "The elevated helper did not return a verified result. It may still "
        "be running, so this action is reported as execution_unknown and must "
        "not be retried automatically.",
        "execution_unknown",
        elevation="unknown",
        status="execution_unknown",
        detail={
            "reason": reason,
            "observed_rule_state": observed,
            "retry_allowed": False,
        },
    )


def _finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


class ElevationAdapter:
    """Disabled-by-default UAC adapter used by the executor."""

    name = "windows-uac"

    def __init__(self, base_dir=None, launcher=None, clock=time.time,
                 timeout=DEFAULT_TIMEOUT, poll=DEFAULT_POLL_SECONDS,
                 enabled=None, install_verifier=None, firewall_runner=None):
        self.base_dir = Path(base_dir or defense_base_dir())
        self._launcher = launcher or launch_elevated
        self._clock = clock
        self.timeout = float(timeout)
        self.poll = float(poll)
        self.enabled = elevation_enabled() if enabled is None else bool(enabled)
        self._install_verifier = install_verifier or verify_helper_installation
        self.firewall_runner = firewall_runner

        # Reject a malformed key immediately when elevation is enabled.  This
        # keeps execute() from ever writing a request signed by a weak key.
        self.secret_error = None
        if self.enabled:
            try:
                load_or_create_secret(self.base_dir)
            except SecretError as exc:
                self.secret_error = exc

    def _installation(self):
        try:
            result = self._install_verifier()
        except Exception as exc:
            return False, f"The installation check failed: {type(exc).__name__}."
        if isinstance(result, tuple) and len(result) == 2:
            return bool(result[0]), str(result[1])
        return bool(result), "Helper installation check completed."

    def status(self):
        if not IS_WINDOWS:
            return {
                "supported": False,
                "enabled": False,
                "adapter": self.name,
                "trusted": False,
                "detail": "Elevation is only available on Windows.",
            }
        if not self.enabled:
            return {
                "supported": True,
                "enabled": False,
                "configured": False,
                "trusted": False,
                "adapter": self.name,
                "detail": (
                    "Disabled by default. Set CYBERGUARD_DEFENSE_ELEVATION=1 "
                    "only after installing a protected helper."
                ),
            }

        trusted, detail = self._installation()
        if self.secret_error is not None:
            return {
                "supported": True,
                "enabled": False,
                "configured": True,
                "trusted": False,
                "adapter": self.name,
                "detail": (
                    "Elevation is configured but the HMAC key failed an "
                    f"integrity check: {self.secret_error.message}"
                ),
            }
        return {
            "supported": True,
            "enabled": bool(trusted),
            "configured": True,
            "trusted": bool(trusted),
            "adapter": self.name,
            "detail": (
                "Enabled. Each state-changing action opens one UAC prompt; "
                "the Flask process stays non-elevated."
                if trusted else
                "Elevation is configured but refused: " + detail
            ),
        }

    def execute(self, action_type, params, action_id):
        """Run one signed request through the helper, never raising."""
        if not IS_WINDOWS:
            return _failure(
                "State-changing actions require Windows.",
                "unsupported_os",
                elevation="unsupported",
            )
        if not self.enabled:
            return _failure(
                "The Windows elevation adapter is disabled. Set "
                "CYBERGUARD_DEFENSE_ELEVATION=1 only after installing a "
                "protected helper.",
                "elevation_disabled",
                elevation="disabled",
            )

        trusted, detail = self._installation()
        if not trusted:
            return _failure(
                "Elevation refused: " + detail,
                "helper_untrusted",
                elevation="untrusted",
            )

        if self.secret_error is not None:
            return _failure(
                "The HMAC key failed an integrity check: "
                f"{self.secret_error.message}",
                self.secret_error.category,
                elevation="failed",
            )

        if action_type not in ELEVATED_ACTIONS:
            return _failure(
                "This action is not allowed through the elevated helper.",
                "action_not_elevatable",
                elevation="failed",
            )
        if not isinstance(action_id, str) or not _ACTION_ID_RE.fullmatch(
            action_id
        ):
            return _failure(
                "Invalid action id.", "invalid_parameters",
                elevation="failed",
            )

        try:
            request_path, payload = self._write_request(
                action_type, params, action_id
            )
        except SecretError as exc:
            return _failure(
                f"Could not prepare the elevated request: {exc.message}",
                exc.category,
                elevation="failed",
            )
        except (OSError, ValueError, security.SecurityError) as exc:
            return _failure(
                f"Could not prepare the elevated request: "
                f"{type(exc).__name__}.",
                "request_write_failed",
                elevation="failed",
            )

        unknown = False
        try:
            code = self._launcher(request_path)
            code = int(code or 0)

            if code == ERROR_CANCELLED:
                return _failure(
                    "The UAC prompt was cancelled; nothing was executed.",
                    "uac_cancelled",
                    elevation="cancelled",
                    status="cancelled",
                )
            if code == ERROR_ACCESS_DENIED:
                return _failure(
                    "Windows denied elevation; nothing was executed.",
                    "uac_denied",
                    elevation="denied",
                )
            if code <= 32:
                return _failure(
                    f"The elevated helper could not be started (code {code}).",
                    "launch_failed",
                    elevation="failed",
                )

            result = self._wait_for_result(request_path, payload)
            unknown = result.get("status") == "execution_unknown"
            return result
        finally:
            self._cleanup(request_path, keep_running=unknown)

    def _write_request(self, action_type, params, action_id):
        secret = load_or_create_secret(self.base_dir)
        directory = requests_dir(self.base_dir)
        security.secure_mkdir(directory, restricted=IS_WINDOWS)
        _prune_consumed(self.base_dir, clock=self._clock)

        nonce = secrets.token_hex(16)
        now = float(self._clock())
        if not math.isfinite(now):
            raise ValueError("The clock returned a non-finite value.")
        payload = {
            "version": 1,
            "nonce": nonce,
            "action_id": action_id,
            "action_type": action_type,
            "params": params,
            "issued_at": now,
            "expires_at": now + REQUEST_TTL_SECONDS,
        }
        signed = {
            "payload": payload,
            "signature": sign_payload(payload, secret),
        }

        request_path = directory / f"{nonce}.json"
        _atomic_write_json(request_path, signed)
        return request_path, payload

    def _observe_rule(self, rule_name):
        try:
            present = firewall.rule_exists(
                rule_name, runner=self.firewall_runner
            )
        except firewall.FirewallCommandError as exc:
            return {
                "state": "unknown",
                "error_category": exc.category,
            }
        return {"state": "present" if present else "absent"}

    def _timeout_result(self, request_path, payload):
        request_path = Path(request_path)
        if _running_path(request_path).exists():
            reason = "helper_still_running"
        elif _consumed_marker(self.base_dir, payload.get("nonce", "")).exists():
            reason = "helper_missing_result"
        elif request_path.exists():
            reason = "helper_not_started"
        else:
            reason = "unknown"

        rule_name = None
        try:
            if payload.get("action_type") == "create_firewall_block_rule":
                rule_name = policy.rule_name_for(payload.get("params") or {})
            elif payload.get("action_type") == "remove_cyberguard_firewall_rule":
                rule_name = (payload.get("params") or {}).get("rule_name")
        except Exception:
            rule_name = None

        observed = (
            self._observe_rule(rule_name)
            if isinstance(rule_name, str) and rule_name
            else {"state": "not_checked"}
        )
        return _unknown_result(reason, observed=observed)

    def _wait_for_result(self, request_path, payload):
        secret = load_or_create_secret(self.base_dir)
        result_path = _result_path(request_path)
        deadline = time.monotonic() + self.timeout

        while time.monotonic() < deadline:
            if result_path.exists():
                try:
                    data = _load_json_file(
                        result_path, MAX_RESULT_BYTES, "invalid_result"
                    )
                except RequestError:
                    time.sleep(self.poll)
                    continue

                if not verify_signed(data, secret):
                    return _failure(
                        "The elevated helper returned an untrusted result.",
                        "invalid_result_signature",
                        elevation="failed",
                    )

                result = data.get("payload")
                if not isinstance(result, dict):
                    return _failure(
                        "The elevated helper returned a malformed result.",
                        "invalid_result",
                        elevation="failed",
                    )

                if (
                    result.get("nonce") != payload["nonce"]
                    or result.get("action_id") != payload["action_id"]
                ):
                    return _failure(
                        "The elevated result does not match the request.",
                        "result_mismatch",
                        elevation="failed",
                    )

                status = result.get("status", "failure")
                if status not in (
                    "success", "unverified", "failure", "cancelled",
                    "execution_unknown",
                ):
                    status = "failure"
                return {
                    "status": status,
                    "changed": bool(result.get("changed")),
                    "verified": result.get("verified"),
                    "error": result.get("error"),
                    "error_category": result.get("error_category"),
                    "elevation": "used",
                    "detail": (
                        result.get("detail")
                        if isinstance(result.get("detail"), dict) else {}
                    ),
                }

            time.sleep(self.poll)

        return self._timeout_result(request_path, payload)

    def _cleanup(self, request_path, keep_running=False):
        stem = Path(request_path).stem
        paths = [
            Path(request_path),
            Path(request_path).with_name(stem + ".result.json"),
            Path(request_path).with_name(stem + ".json.tmp"),
        ]
        if not keep_running:
            paths.append(Path(request_path).with_name(stem + ".running"))
        for path in paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


# --------------------------------------------------------------- helper side


def _validate_request_path(path, directory):
    candidate = Path(path)

    # A missing request file is a normal replay/consumption outcome: the
    # parent and name checks below still apply, and reading the file later
    # fails closed.  Only an existing path is subject to the harder checks.
    if candidate.exists() or candidate.is_symlink():
        if security.is_reparse_point(candidate):
            raise ValueError("request file is a symlink or reparse point")

        try:
            details = os.lstat(candidate)
        except OSError as exc:
            raise ValueError("request file cannot be inspected") from exc
        if getattr(details, "st_nlink", 1) != 1:
            raise ValueError("request file has multiple hard links")

    resolved = candidate.resolve()
    expected = Path(directory).resolve()

    if os.path.normcase(str(resolved.parent)) != os.path.normcase(
        str(expected)
    ):
        raise ValueError("request file is outside the request directory")
    if not _REQUEST_NAME_RE.fullmatch(resolved.name):
        raise ValueError("request file name is not a CyberGuard nonce")


def _validate_ownership_record(registry, rule_name):
    try:
        record = registry.get_validated(rule_name)
    except firewall.RegistryError as exc:
        return None, (
            "The ownership registry is corrupt or unreadable; refusing the "
            "removal.",
            "ownership_registry_corrupt",
        )
    if record is None:
        return None, (
            "The rule is not recorded as CyberGuard-owned.",
            "not_owned",
        )
    return record, None


def _execute_payload(payload):
    action_type = payload.get("action_type")
    params = payload.get("params")

    if action_type not in ELEVATED_ACTIONS:
        return _failure(
            "The helper does not support this action type.",
            "action_not_elevatable",
            elevation="used",
        )

    try:
        canonical = policy.validate_action(action_type, params)
    except Exception as exc:
        return _failure(
            f"Revalidation failed: {type(exc).__name__}.",
            getattr(exc, "error_category", "invalid_parameters"),
            elevation="used",
        )

    if canonical_json(canonical) != canonical_json(params):
        return _failure(
            "The request parameters are not canonical.",
            "invalid_parameters",
            elevation="used",
        )

    if action_type == "create_firewall_block_rule":
        rule_name = policy.rule_name_for(canonical)
        data = firewall.create_rule(rule_name, canonical)
        expected_params = canonical
    else:
        rule_name = canonical["rule_name"]

        # Independent ownership re-check inside the elevated helper: the
        # signed request is necessary but not sufficient.  A removal is only
        # allowed for a rule CyberGuard recorded as its own, and the recorded
        # parameters must still derive the exact same rule identity.
        registry = firewall.RuleRegistry(
            defense_base_dir() / "rules.json"
        )
        record, problem = _validate_ownership_record(registry, rule_name)
        if problem is not None:
            return _failure(
                problem[0],
                problem[1],
                elevation="used",
                detail={"rule_name": rule_name},
            )
        expected_params = record.get("params")
        data = firewall.remove_rule(
            rule_name, expected_params=expected_params
        )

    detail = {
        "rule_name": rule_name,
        "already_exists": bool(data.get("already_exists")),
        "already_absent": bool(data.get("already_absent")),
    }

    if data.get("ok"):
        verified = bool(data.get("verified"))
        return {
            "status": "success" if verified else "unverified",
            "changed": bool(data.get("changed")),
            "verified": verified,
            "error": None,
            "error_category": None,
            "elevation": "used",
            "detail": detail,
        }

    return _failure(
        data.get("error") or "The firewall operation failed.",
        data.get("error_category") or "firewall_command_failed",
        elevation="used",
        detail=detail,
    )


def _write_helper_result(request_path, payload, result):
    secret = load_or_create_secret()
    result_payload = {
        "nonce": payload.get("nonce"),
        "action_id": payload.get("action_id"),
        **result,
    }
    signed = {
        "payload": result_payload,
        "signature": sign_payload(result_payload, secret),
    }
    _atomic_write_json(_result_path(request_path), signed)


def _safe_result_write(request_path, payload, result):
    try:
        _write_helper_result(request_path, payload, result)
    except (SecretError, OSError, security.SecurityError, ValueError):
        # Nothing else can be done safely; the caller will see a missing result
        # and must treat the execution as unknown rather than success.
        pass


def helper_main(argv=None):
    """Entry point for the elevated module. Never called by the web process."""
    parser = argparse.ArgumentParser(
        description="CyberGuard one-shot elevated helper."
    )
    parser.add_argument("--request", required=True)
    args = parser.parse_args(argv)

    if not IS_WINDOWS:
        return 2

    base = defense_base_dir()
    request_path = Path(args.request)

    try:
        _validate_request_path(request_path, requests_dir(base))
    except (ValueError, security.SecurityError):
        return 2

    if not is_admin():
        return 3

    try:
        data = _load_json_file(request_path, MAX_REQUEST_BYTES, "invalid_request")
    except RequestError:
        return 4

    try:
        secret = load_or_create_secret(base)
    except SecretError:
        return 6

    if not verify_signed(data, secret):
        return 4

    payload = data.get("payload")
    if not isinstance(payload, dict):
        return 4

    now = time.time()
    expires_at = payload.get("expires_at")
    issued_at = payload.get("issued_at")
    nonce = payload.get("nonce")

    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce) or (
        request_path.stem != nonce
    ):
        _safe_result_write(
            request_path, payload,
            _failure("Request nonce mismatch.", "invalid_request",
                     elevation="used"),
        )
        return 5

    if not _finite_number(expires_at) or not _finite_number(issued_at):
        _safe_result_write(
            request_path, payload,
            _failure("The request timestamps are not finite.",
                     "invalid_request", elevation="used"),
        )
        return 5

    issued_at = float(issued_at)
    expires_at = float(expires_at)

    if expires_at < issued_at:
        _safe_result_write(
            request_path, payload,
            _failure("The request expiry precedes its issue time.",
                     "invalid_request", elevation="used"),
        )
        return 5

    if expires_at - issued_at > REQUEST_TTL_SECONDS + MAX_CLOCK_SKEW_SECONDS:
        _safe_result_write(
            request_path, payload,
            _failure("The request validity window is too long.",
                     "invalid_request", elevation="used"),
        )
        return 5

    if now > expires_at:
        _safe_result_write(
            request_path, payload,
            _failure("The elevated request expired.", "request_expired",
                     elevation="used"),
        )
        return 5

    if issued_at > now + MAX_CLOCK_SKEW_SECONDS:
        _safe_result_write(
            request_path, payload,
            _failure("The request timestamp is not acceptable.",
                     "invalid_request", elevation="used"),
        )
        return 5

    if now - issued_at > REQUEST_TTL_SECONDS + MAX_CLOCK_SKEW_SECONDS:
        _safe_result_write(
            request_path, payload,
            _failure("The request is older than its permitted window.",
                     "request_expired", elevation="used"),
        )
        return 5

    try:
        _prune_consumed(base)
        _mark_consumed(base, nonce)
    except ReplayDetected as exc:
        _safe_result_write(
            request_path, payload,
            _failure(exc.message, exc.category, elevation="used"),
        )
        return 5
    except (OSError, security.SecurityError):
        _safe_result_write(
            request_path, payload,
            _failure("The replay ledger could not be updated safely.",
                     "replay_state_unavailable", elevation="used"),
        )
        return 5

    running = _running_path(request_path)
    try:
        os.replace(request_path, running)
    except OSError:
        _safe_result_write(
            request_path, payload,
            _failure("This request was already consumed.",
                     "replay_detected", elevation="used"),
        )
        return 5

    try:
        result = _execute_payload(payload)
        _safe_result_write(request_path, payload, result)
        return 0 if result["status"] in ("success", "unverified") else 5
    finally:
        try:
            running.unlink(missing_ok=True)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(helper_main())
