"""Windows Firewall rule operations using fixed ``netsh`` argv lists.

Nothing here builds a shell command: every argument is a separate list item
and :mod:`subprocess` is used with ``shell=False``.  In production ``netsh`` is
resolved to ``%SystemRoot%\\System32\\netsh.exe`` rather than through ``PATH``.

Security rules
--------------
* A non-zero ``netsh show rule`` exit is **not** automatically "absent".
  Absent, access-denied, command failure, unsupported output and malformed
  output are distinct states.
* Creation and removal are only reported as successful after the exact
  expected rule (including its important properties) is verified.
* Ownership records are validated: a name alone is never enough.  The recorded
  parameters must still canonicalise to the same ``CyberGuard-`` identity.
* A corrupt registry is fail-closed and is never silently replaced by an empty
  one.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from defense.models import canonical_json
from defense.policy import RULE_NAME_RE, RULE_PREFIX, rule_name_for
from defense.windows import security

IS_WINDOWS = security.IS_WINDOWS

NETSH = security.trusted_system32_executable("netsh.exe")
DEFAULT_TIMEOUT = 30
MAX_HISTORY = 50
MAX_REGISTRY_BYTES = 1024 * 1024

_ACTION_ID_RE = re.compile(r"^[a-f0-9]{32}$")
_FIELD_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /_-]*?)\s*:\s*(.*?)\s*$")
_RULE_NAME_FIELD = "rule name"

_ABSENT_MARKERS = (
    "no rules match",
    "no rules in the",
    "specified criteria",
    "no matching rules",
)
_ACCESS_DENIED_MARKERS = (
    "access is denied",
    "requires elevation",
    "requested operation requires elevation",
    "elevated",
    "administrator",
)


class FirewallCommandError(Exception):
    def __init__(self, message, category="firewall_command_failed"):
        super().__init__(message)
        self.message = str(message)
        self.category = category


class RegistryError(Exception):
    """The ownership registry is corrupt or cannot be trusted."""

    def __init__(self, message, category="ownership_registry_corrupt"):
        super().__init__(message)
        self.message = str(message)
        self.category = category


def _run(argv, runner=None, timeout=DEFAULT_TIMEOUT):
    """Run a fixed argv list; return ``(returncode, stdout, stderr)``."""
    if not isinstance(argv, (list, tuple)) or not argv:
        raise FirewallCommandError(
            "A fixed executable and argv list are required.",
            "invalid_command",
        )
    if IS_WINDOWS and argv[0] != NETSH:
        raise FirewallCommandError(
            "Refusing to run an executable outside the trusted System32 path.",
            "untrusted_executable",
        )

    runner = runner or subprocess.run
    try:
        completed = runner(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise FirewallCommandError(
            f"The firewall command timed out after {timeout} seconds.",
            "timeout",
        ) from None
    except FileNotFoundError:
        raise FirewallCommandError(
            "The 'netsh' command is not available.", "command_not_found"
        ) from None
    except OSError as exc:
        raise FirewallCommandError(
            f"The firewall command could not be started: "
            f"{type(exc).__name__}.",
            "command_failed",
        ) from None

    return (
        int(getattr(completed, "returncode", 1)),
        getattr(completed, "stdout", "") or "",
        getattr(completed, "stderr", "") or "",
    )


def _validate_rule_name(rule_name):
    if not isinstance(rule_name, str) or not RULE_NAME_RE.fullmatch(rule_name):
        raise FirewallCommandError(
            "Refusing to use a name that is not an exact CyberGuard rule name.",
            "not_owned",
        )
    if not rule_name.startswith(RULE_PREFIX):
        raise FirewallCommandError(
            "Refusing to build a rule without the CyberGuard prefix.",
            "not_owned",
        )
    return rule_name


def build_add_rule_argv(rule_name, params):
    """Build the exact ``netsh`` argv for one block rule.

    This function independently validates every input.  It never assumes that
    a caller already passed through the API policy layer.
    """
    from defense import policy

    try:
        canonical = policy.validate_action(
            "create_firewall_block_rule", params
        )
    except Exception as exc:
        raise FirewallCommandError(
            f"The rule parameters are invalid ({type(exc).__name__}).",
            "invalid_parameters",
        ) from None

    if canonical_json(canonical) != canonical_json(params):
        raise FirewallCommandError(
            "The rule parameters are not canonical.", "invalid_parameters"
        )

    _validate_rule_name(rule_name)
    if rule_name != rule_name_for(canonical):
        raise FirewallCommandError(
            "Rule name does not match the canonical parameters.", "not_owned"
        )

    direction = "in" if canonical["direction"] == "inbound" else "out"
    protocol = {
        "tcp": "TCP",
        "udp": "UDP",
        "any": "any",
    }[canonical["protocol"]]

    argv = [
        NETSH,
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        f"dir={direction}",
        "action=block",
        f"protocol={protocol}",
        f"remoteip={canonical['remote_address']}",
    ]

    if canonical.get("local_port"):
        argv.append(f"localport={canonical['local_port']}")
    if canonical.get("remote_port"):
        argv.append(f"remoteport={canonical['remote_port']}")

    argv.extend([
        f"profile={canonical['profile']}",
        "enable=yes",
        "description=CyberGuard-AI-managed-rule",
    ])
    return argv


def build_show_rule_argv(rule_name):
    _validate_rule_name(rule_name)
    return [
        NETSH, "advfirewall", "firewall", "show", "rule",
        f"name={rule_name}", "verbose",
    ]


def build_delete_rule_argv(rule_name):
    _validate_rule_name(rule_name)
    return [
        NETSH, "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ]


def _is_absent_text(text):
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _ABSENT_MARKERS)


def _is_access_denied(text):
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _ACCESS_DENIED_MARKERS)


def parse_rules(text):
    """Parse ``netsh ... show rule ... verbose`` output into rule dictionaries.

    The parser keys off the English ``Rule Name:`` label.  Localized output
    that does not contain it is reported as unsupported rather than guessed.
    """
    rules = []
    current = None
    for line in (text or "").splitlines():
        match = _FIELD_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        if key == _RULE_NAME_FIELD:
            if current is not None:
                rules.append(current)
            current = {"rule_name": value}
        elif current is not None:
            current[key.replace(" ", "_")] = value
    if current is not None:
        rules.append(current)
    return rules


def _classify_nonzero(code, text):
    if _is_absent_text(text):
        return "absent"
    if _is_access_denied(text):
        return "access_denied"
    return "failed"


def query_rule(rule_name, runner=None):
    """Return a structured rule-query result.

    ``state`` is one of ``present``, ``absent``, ``access_denied``,
    ``unsupported_output``, ``malformed_output``, ``command_failed`` or
    ``timeout``.  Only ``present`` and ``absent`` are definitive.
    """
    _validate_rule_name(rule_name)
    try:
        code, stdout, stderr = _run(
            build_show_rule_argv(rule_name), runner=runner
        )
    except FirewallCommandError as exc:
        return {
            "state": "timeout" if exc.category == "timeout" else "command_failed",
            "error": exc.message,
            "error_category": exc.category,
        }

    text = f"{stdout}\n{stderr}"
    if code != 0:
        category = _classify_nonzero(code, text)
        if category == "absent":
            return {"state": "absent", "raw": text[:4000]}
        if category == "access_denied":
            return {
                "state": "access_denied",
                "error": "Access to the firewall rule list was denied.",
                "error_category": "access_denied",
            }
        detail = (stderr or stdout).strip().splitlines()
        return {
            "state": "command_failed",
            "error": (
                f"netsh show rule failed with code {code}"
                + (f": {detail[0][:160]}" if detail else ".")
            ),
            "error_category": "firewall_command_failed",
        }

    if _is_absent_text(text):
        return {"state": "absent", "raw": text[:4000]}

    rules = parse_rules(stdout)
    if not rules:
        return {
            "state": "unsupported_output",
            "error": (
                "netsh returned output that could not be parsed; the rule "
                "cannot be considered verified."
            ),
            "error_category": "unsupported_firewall_output",
            "raw": stdout[:4000],
        }

    matches = [rule for rule in rules if rule.get("rule_name") == rule_name]
    if not matches:
        return {"state": "absent", "raw": stdout[:4000]}
    if len(matches) > 1:
        return {
            "state": "malformed_output",
            "error": "netsh returned duplicate rules with the same name.",
            "error_category": "malformed_firewall_output",
        }
    return {"state": "present", "rule": matches[0], "raw": stdout[:4000]}


def _normalise(value):
    return (value or "").strip().strip(",").lower()


def _network_text(value):
    text = (value or "").strip()
    if _normalise(text) in ("any", "*"):
        return "any"
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return text.lower()


def _port_text(value):
    text = (value or "").strip()
    if _normalise(text) in ("any", "*"):
        return "any"
    return text.replace(" ", "")


def _profile_set(value):
    text = _normalise(value)
    if text in ("any", "all", "*"):
        return {"any"}
    return {part.strip() for part in text.split(",") if part.strip()}


def verify_rule_properties(rule, params):
    """Check that a parsed rule exactly matches the intended canonical action."""
    from defense import policy

    try:
        canonical = policy.validate_action(
            "create_firewall_block_rule", params
        )
    except Exception:
        return False, "The expected parameters are invalid."

    checks = []

    def check(label, actual, expected):
        checks.append((label, _normalise(actual), _normalise(expected)))

    check("action", rule.get("action"), "block")
    check("enabled", rule.get("enabled"), "yes")
    check(
        "direction",
        rule.get("direction"),
        "in" if canonical["direction"] == "inbound" else "out",
    )
    check(
        "protocol",
        rule.get("protocol"),
        canonical["protocol"] if canonical["protocol"] != "any" else "any",
    )
    check(
        "remoteip",
        rule.get("remoteip"),
        canonical["remote_address"],
    )
    check(
        "localip",
        rule.get("localip", "Any"),
        "any",
    )
    check(
        "localport",
        _port_text(rule.get("localport", "Any")),
        _port_text(canonical.get("local_port") or "any"),
    )
    check(
        "remoteport",
        _port_text(rule.get("remoteport", "Any")),
        _port_text(canonical.get("remote_port") or "any"),
    )

    profiles = _profile_set(rule.get("profiles"))
    expected_profiles = _profile_set(canonical["profile"])
    if "any" not in expected_profiles and "any" not in profiles:
        if profiles != expected_profiles:
            return (
                False,
                f"profiles mismatch ({rule.get('profiles')!r} != "
                f"{canonical['profile']!r})",
            )

    # Normalise network values before comparing because netsh may add /32.
    for label, actual, expected in list(checks):
        if label == "remoteip":
            actual, expected = _network_text(actual), _network_text(expected)
        if (label in ("localip", "localport", "remoteport")
                and actual in ("any", "*")):
            actual = "any"
        if actual != expected:
            return False, f"{label} mismatch ({actual!r} != {expected!r})"
    return True, "verified"


def _result(ok, changed, verified, rule_name, error=None, error_category=None,
            already_exists=False, already_absent=False):
    return {
        "ok": bool(ok),
        "changed": bool(changed),
        "verified": bool(verified),
        "already_exists": bool(already_exists),
        "already_absent": bool(already_absent),
        "rule_name": rule_name,
        "error": error,
        "error_category": error_category,
    }


def _query_failure(query, rule_name):
    return _result(
        False,
        False,
        False,
        rule_name,
        error=query.get("error") or "The firewall rule query failed.",
        error_category=query.get("error_category", "firewall_command_failed"),
    )


def rule_exists(rule_name, runner=None):
    """Return True only when the exact rule is present and the query is definitive.

    Raises :class:`FirewallCommandError` for access-denied, command failure,
    timeout, unsupported or malformed output.  Treating those as "absent" was
    the previous, unsafe behaviour.
    """
    query = query_rule(rule_name, runner=runner)
    state = query["state"]
    if state == "present":
        return True
    if state == "absent":
        return False
    raise FirewallCommandError(
        query.get("error") or "The firewall rule query was not definitive.",
        query.get("error_category", "firewall_query_failed"),
    )


def create_rule(rule_name, params, runner=None):
    """Create one rule idempotently and verify the exact resulting properties."""
    try:
        argv = build_add_rule_argv(rule_name, params)
    except FirewallCommandError as exc:
        return _result(False, False, False, rule_name,
                       error=exc.message, error_category=exc.category)

    query = query_rule(rule_name, runner=runner)
    if query["state"] == "present":
        matches, reason = verify_rule_properties(query["rule"], params)
        if not matches:
            return _result(
                False, False, False, rule_name,
                error=f"A rule with this name already exists but does not "
                      f"match the intended action: {reason}.",
                error_category="rule_conflict",
            )
        return _result(
            True, False, True, rule_name, already_exists=True
        )
    if query["state"] != "absent":
        return _query_failure(query, rule_name)

    try:
        code, stdout, stderr = _run(argv, runner=runner)
    except FirewallCommandError as exc:
        return _result(False, False, False, rule_name,
                       error=exc.message, error_category=exc.category)

    if code != 0:
        text = f"{stdout}\n{stderr}"
        category = _classify_nonzero(code, text)
        if category == "access_denied":
            return _result(
                False, False, False, rule_name,
                error="Access was denied while creating the firewall rule.",
                error_category="access_denied",
            )
        detail = (stderr or stdout).strip().splitlines()
        return _result(
            False, False, False, rule_name,
            error=(
                f"netsh add rule failed with code {code}"
                + (f": {detail[0][:160]}" if detail else ".")
            ),
            error_category="firewall_command_failed",
        )

    query = query_rule(rule_name, runner=runner)
    if query["state"] != "present":
        if query["state"] == "absent":
            return _result(
                False, False, False, rule_name,
                error="The rule could not be verified after creation.",
                error_category="verification_failed",
            )
        return _query_failure(query, rule_name)

    matches, reason = verify_rule_properties(query["rule"], params)
    if not matches:
        return _result(
            False, False, False, rule_name,
            error=f"The created rule did not match the intended action: "
                  f"{reason}.",
            error_category="verification_failed",
        )
    return _result(True, True, True, rule_name)


def remove_rule(rule_name, expected_params=None, runner=None):
    """Delete one positively identified CyberGuard rule and verify absence."""
    try:
        _validate_rule_name(rule_name)
    except FirewallCommandError as exc:
        return _result(False, False, False, rule_name,
                       error=exc.message, error_category=exc.category)

    query = query_rule(rule_name, runner=runner)
    if query["state"] == "absent":
        return _result(True, False, True, rule_name, already_absent=True)
    if query["state"] != "present":
        return _query_failure(query, rule_name)

    if expected_params is not None:
        matches, reason = verify_rule_properties(
            query["rule"], expected_params
        )
        if not matches:
            return _result(
                False, False, False, rule_name,
                error=(
                    "The firewall rule does not match the recorded ownership "
                    f"parameters: {reason}."
                ),
                error_category="ownership_mismatch",
            )

    try:
        code, stdout, stderr = _run(
            build_delete_rule_argv(rule_name), runner=runner
        )
    except FirewallCommandError as exc:
        return _result(False, False, False, rule_name,
                       error=exc.message, error_category=exc.category)

    if code != 0:
        text = f"{stdout}\n{stderr}"
        category = _classify_nonzero(code, text)
        if category == "access_denied":
            return _result(
                False, False, False, rule_name,
                error="Access was denied while deleting the firewall rule.",
                error_category="access_denied",
            )
        detail = (stderr or stdout).strip().splitlines()
        return _result(
            False, False, False, rule_name,
            error=(
                f"netsh delete rule failed with code {code}"
                + (f": {detail[0][:160]}" if detail else ".")
            ),
            error_category="firewall_command_failed",
        )

    query = query_rule(rule_name, runner=runner)
    if query["state"] == "absent":
        return _result(True, True, True, rule_name)
    if query["state"] == "present":
        return _result(
            False, False, False, rule_name,
            error="The rule is still present after deletion.",
            error_category="verification_failed",
        )
    return _query_failure(query, rule_name)


def _finite(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


class RuleRegistry:
    """CyberGuard's own record of the rules it created.

    This is ownership metadata, not a security boundary.  The helper still
    requires the exact ``CyberGuard-`` name and re-derives the expected rule
    identity from the recorded parameters before any removal.
    """

    def __init__(self, path, clock=time.time, max_history=MAX_HISTORY,
                 max_bytes=MAX_REGISTRY_BYTES):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._clock = clock
        self._max_history = int(max_history)
        self._max_bytes = int(max_bytes)
        self._loaded = False
        self._corrupt = False
        self._invalid_entries = 0
        self._error = None
        self._data = {"version": 1, "active": {}, "removed": []}

    # ------------------------------------------------------------- loading
    def _validate_record(self, name, record):
        if not isinstance(name, str) or not RULE_NAME_RE.fullmatch(name):
            return None
        if not isinstance(record, dict):
            return None

        from defense import policy

        params = record.get("params")
        if not isinstance(params, dict):
            return None
        try:
            canonical = policy.validate_action(
                "create_firewall_block_rule", params
            )
        except Exception:
            return None
        if policy.rule_name_for(canonical) != name:
            return None

        action_id = record.get("action_id")
        if action_id is not None and (
            not isinstance(action_id, str)
            or not _ACTION_ID_RE.fullmatch(action_id)
        ):
            return None

        for key in ("created_at", "expires_at", "recorded_at", "removed_at"):
            value = record.get(key)
            if value is not None and not _finite(value):
                return None

        cleaned = dict(record)
        cleaned["rule_name"] = name
        cleaned["params"] = canonical
        return cleaned

    def _load(self):
        if self._loaded:
            return
        self._loaded = True

        if not self.path.exists():
            return

        try:
            raw = security.secure_read(self.path, self._max_bytes)
            data = json.loads(
                raw.decode("utf-8"),
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"non-finite {value}")
                ),
            )
        except (OSError, ValueError, UnicodeDecodeError,
                security.SecurityError) as exc:
            self._corrupt = True
            self._error = f"The ownership registry could not be read: {type(exc).__name__}."
            return

        if not isinstance(data, dict):
            self._corrupt = True
            self._error = "The ownership registry is not a JSON object."
            return
        if data.get("version") != 1:
            self._corrupt = True
            self._error = "The ownership registry has an unknown version."
            return

        active = data.get("active")
        removed = data.get("removed")
        if not isinstance(active, dict) or not isinstance(removed, list):
            self._corrupt = True
            self._error = "The ownership registry has an invalid structure."
            return

        valid_active = {}
        for name, record in active.items():
            cleaned = self._validate_record(name, record)
            if cleaned is None:
                self._invalid_entries += 1
                continue
            valid_active[name] = cleaned

        valid_removed = []
        for record in removed[-self._max_history:]:
            if not isinstance(record, dict):
                self._invalid_entries += 1
                continue
            name = record.get("rule_name")
            cleaned = self._validate_record(name, record)
            if cleaned is None:
                self._invalid_entries += 1
                continue
            valid_removed.append(cleaned)

        self._data["active"] = valid_active
        self._data["removed"] = valid_removed

    def _ensure_healthy(self):
        self._load()
        if self._corrupt:
            raise RegistryError(
                self._error or "The ownership registry is corrupt."
            )
        if self._invalid_entries:
            raise RegistryError(
                "The ownership registry contains malformed records; refusing "
                "to overwrite it."
            )

    # -------------------------------------------------------------- saving
    def _save(self):
        self._ensure_healthy()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            self._data, indent=2, sort_keys=True, allow_nan=False
        ).encode("utf-8")
        security.secure_atomic_write(
            self.path, payload, mode=0o600, restricted=IS_WINDOWS
        )

    # ------------------------------------------------------------- queries
    def get(self, rule_name):
        with self._lock:
            self._load()
            if self._corrupt:
                return None
            record = self._data["active"].get(rule_name)
            return dict(record) if isinstance(record, dict) else None

    def get_validated(self, rule_name):
        """Return a record only when it is structurally valid and owned."""
        with self._lock:
            self._load()
            if self._corrupt:
                raise RegistryError(
                    self._error or "The ownership registry is corrupt."
                )
            record = self._data["active"].get(rule_name)
            if not isinstance(record, dict):
                return None
            cleaned = self._validate_record(rule_name, record)
            if cleaned is None:
                return None
            return dict(cleaned)

    def is_owned(self, rule_name):
        try:
            return self.get_validated(rule_name) is not None
        except RegistryError:
            return False

    def assert_owned(self, rule_name):
        """Like :meth:`is_owned`, but reports corruption instead of hiding it."""
        return self.get_validated(rule_name)

    def list_active(self):
        with self._lock:
            self._load()
            if self._corrupt:
                return []
            return [dict(record) for record in self._data["active"].values()]

    def list_removed(self):
        with self._lock:
            self._load()
            if self._corrupt:
                return []
            return [dict(record) for record in self._data["removed"]]

    def health(self):
        with self._lock:
            self._load()
            return {
                "healthy": not self._corrupt and not self._invalid_entries,
                "corrupt": bool(self._corrupt),
                "invalid_entries": int(self._invalid_entries),
                "error": self._error,
            }

    # ------------------------------------------------------------ mutations
    def upsert(self, record):
        with self._lock:
            self._load()
            self._ensure_healthy()
            name = record.get("rule_name") if isinstance(record, dict) else None
            cleaned = self._validate_record(name, record)
            if cleaned is None:
                raise ValueError(
                    "record must carry a valid CyberGuard rule name and "
                    "canonical parameters"
                )
            cleaned.setdefault("recorded_at", float(self._clock()))
            self._data["active"][name] = cleaned
            self._save()
            return dict(cleaned)

    def mark_removed(self, rule_name, action_id=None):
        with self._lock:
            self._load()
            self._ensure_healthy()
            if not isinstance(rule_name, str) or not RULE_NAME_RE.fullmatch(
                rule_name
            ):
                raise ValueError("rule_name must be a CyberGuard rule name")
            record = self._data["active"].pop(rule_name, None)
            if record is not None:
                record = dict(record)
                record["removed_at"] = float(self._clock())
                if action_id is not None:
                    if not isinstance(action_id, str) or not _ACTION_ID_RE.fullmatch(
                        action_id
                    ):
                        raise ValueError("action_id is malformed")
                    record["removed_by_action_id"] = action_id
                self._data["removed"].append(record)
                self._data["removed"] = self._data["removed"][
                    -self._max_history:
                ]
                self._save()
            return dict(record) if isinstance(record, dict) else None

    def expired(self):
        now = float(self._clock())
        with self._lock:
            self._load()
            if self._corrupt:
                return []
            return [
                dict(record)
                for record in self._data["active"].values()
                if float(record.get("expires_at", 0)) <= now
            ]

    def clear(self):
        with self._lock:
            self._data = {"version": 1, "active": {}, "removed": []}
            self._loaded = True
            self._corrupt = False
            self._invalid_entries = 0
            self._error = None
            try:
                self._save()
            except (OSError, RegistryError):
                pass
