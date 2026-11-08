"""Windows-specific read-only inspection.

Every command is a fixed argv list executed with ``shell=False``. No string
from a request, the browser or a language model ever reaches a command line.
Tests inject ``runner`` so no real command (and no real firewall state) is
touched during the test suite.

This module cannot change system state: it only runs ``tasklist``, ``netstat``
and ``netsh ... show``.
"""

from __future__ import annotations

import csv
import io
import re
import subprocess
import sys

from defense.models import UnknownActionError, iso, new_id, utc_now
from defense.windows import security

IS_WINDOWS = sys.platform == "win32"

# Resolved through the trusted System32 path, never through an uncontrolled
# PATH or the current working directory.
TASKLIST = security.trusted_system32_executable("tasklist.exe")
NETSTAT = security.trusted_system32_executable("netstat.exe")
NETSH = security.trusted_system32_executable("netsh.exe")

DEFAULT_TIMEOUT = 10
MAX_RAW_CHARS = 4000
MAX_PARSE_ROWS = 5000

INSPECTION_ACTIONS = (
    "list_processes",
    "list_network_connections",
    "get_firewall_status",
    "generate_incident_report",
)

_PROFILE_RE = re.compile(
    r"(?im)^\s*(Domain|Private|Public)\s+Profile\s+Settings"
)
_STATE_RE = re.compile(r"(?im)^\s*(?:State|Status)\s*[:=]?\s*(ON|OFF)\b")


class CommandError(Exception):
    """A fixed inspection command could not be run or failed."""

    def __init__(self, message, category="command_failed"):
        super().__init__(message)
        self.message = str(message)
        self.category = category


def _run(argv, runner=None, timeout=DEFAULT_TIMEOUT):
    """Run a fixed argv list without a shell and return stdout."""
    if not isinstance(argv, (list, tuple)) or not argv:
        raise CommandError("A fixed argv list is required.", "invalid_command")
    if IS_WINDOWS and argv[0] not in (TASKLIST, NETSTAT, NETSH):
        raise CommandError(
            "Refusing to run an executable outside the trusted System32 path.",
            "untrusted_executable",
        )

    runner = runner or subprocess.run

    try:
        completed = runner(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise CommandError(
            f"The command timed out after {timeout} seconds.", "timeout"
        ) from None
    except FileNotFoundError:
        raise CommandError(
            "The command is not available on this system.",
            "command_not_found",
        ) from None
    except OSError as exc:
        raise CommandError(
            f"The command could not be started: {type(exc).__name__}.",
            "command_failed",
        ) from None

    returncode = getattr(completed, "returncode", 1)
    stdout = getattr(completed, "stdout", "") or ""
    stderr = getattr(completed, "stderr", "") or ""

    if returncode != 0:
        detail = (stderr or stdout).strip().splitlines()
        suffix = f" ({detail[0][:120]})" if detail else ""
        raise CommandError(
            f"The command exited with code {returncode}{suffix}.",
            "command_failed",
        )

    return stdout


def _require_windows():
    if not IS_WINDOWS:
        raise CommandError(
            "This inspection is only available on Windows.", "unsupported_os"
        )


def _unavailable(action_type, error):
    return {
        "available": False,
        "action_type": action_type,
        "error": getattr(error, "message", str(error)),
        "error_category": getattr(error, "category", "command_failed"),
    }


def parse_tasklist(text, limit):
    """Parse ``tasklist /FO CSV /NH`` output into bounded rows."""
    rows = []
    truncated = False

    for index, row in enumerate(csv.reader(io.StringIO(text))):
        if index >= MAX_PARSE_ROWS:
            truncated = True
            break
        if len(row) < 5:
            continue
        image, pid, session, session_number, memory = row[:5]
        pid = pid.strip()
        if not pid.isdigit():
            continue
        if len(rows) >= limit:
            truncated = True
            break
        rows.append({
            "name": image.strip()[:120],
            "pid": int(pid),
            "session": session.strip()[:80],
            "session_number": session_number.strip()[:20],
            "memory": memory.strip()[:40],
        })

    return rows, truncated


def parse_netstat(text, limit, protocol="all"):
    """Parse ``netstat -ano`` output into bounded TCP/UDP rows."""
    rows = []
    truncated = False

    for index, line in enumerate(text.splitlines()):
        if index >= MAX_PARSE_ROWS:
            truncated = True
            break

        parts = line.split()
        if len(parts) < 4:
            continue

        proto = parts[0].lower()
        if proto not in ("tcp", "udp"):
            continue
        if protocol != "all" and proto != protocol:
            continue

        if proto == "tcp":
            if len(parts) < 5:
                continue
            local, remote, state, pid = parts[1], parts[2], parts[3], parts[4]
        else:
            local, remote, pid = parts[1], parts[2], parts[3]
            state = ""

        if not pid.isdigit():
            continue

        if len(rows) >= limit:
            truncated = True
            break

        rows.append({
            "protocol": proto.upper(),
            "local": local[:80],
            "remote": remote[:80],
            "state": (state or "-")[:40],
            "pid": int(pid),
        })

    return rows, truncated


def parse_firewall_state(text):
    """Best-effort parse of ``netsh advfirewall show allprofiles state``.

    Returns ``(profiles, parsed)``. If the localized output does not contain
    recognisable ``State ON/OFF`` lines, ``parsed`` is False and the caller
    still gets the raw text rather than a guess.
    """
    states = [match.group(1).upper() for match in _STATE_RE.finditer(text)]
    names = [match.group(1).lower() for match in _PROFILE_RE.finditer(text)]

    if not states:
        return [], False

    if len(names) != len(states):
        names = ["domain", "private", "public"][:len(states)]

    profiles = [
        {"profile": name, "enabled": value == "ON"}
        for name, value in zip(names, states)
    ]
    return profiles, True


def list_processes(params, runner=None):
    _require_windows()
    output = _run([TASKLIST, "/FO", "CSV", "/NH"], runner=runner)
    rows, truncated = parse_tasklist(output, params["limit"])
    return {
        "available": True,
        "action_type": "list_processes",
        "platform": "windows",
        "processes": rows,
        "count": len(rows),
        "limit": params["limit"],
        "truncated": truncated,
        "state_changed": False,
    }


def list_network_connections(params, runner=None):
    _require_windows()
    output = _run([NETSTAT, "-ano"], runner=runner)
    rows, truncated = parse_netstat(
        output, params["limit"], protocol=params["protocol"]
    )
    return {
        "available": True,
        "action_type": "list_network_connections",
        "platform": "windows",
        "connections": rows,
        "count": len(rows),
        "limit": params["limit"],
        "protocol": params["protocol"],
        "truncated": truncated,
        "state_changed": False,
    }


def get_firewall_status(params, runner=None):
    _require_windows()
    output = _run(
        [NETSH, "advfirewall", "show", "allprofiles", "state"], runner=runner
    )
    profiles, parsed = parse_firewall_state(output)
    return {
        "available": True,
        "action_type": "get_firewall_status",
        "platform": "windows",
        "profiles": profiles,
        "parsed": parsed,
        "raw": output[:MAX_RAW_CHARS] if params.get("include_raw", True) else None,
        "state_changed": False,
        "note": (
            None if parsed else
            "The firewall output could not be parsed; see the raw text."
        ),
    }


def generate_incident_report(params, runner=None):
    """Build an in-memory report. No file and no Windows state is touched."""
    return {
        "available": True,
        "action_type": "generate_incident_report",
        "report_id": new_id(),
        "generated_at": iso(utc_now().timestamp()),
        "title": params["title"],
        "threat_type": params["threat_type"],
        "risk": params["risk"],
        "notes": params.get("notes"),
        "summary": (
            "Incident report generated locally by CyberGuard AI. "
            "No system state was changed and no file was written."
        ),
        "state_changed": False,
    }


_HANDLERS = {
    "list_processes": list_processes,
    "list_network_connections": list_network_connections,
    "get_firewall_status": get_firewall_status,
    "generate_incident_report": generate_incident_report,
}


def run_inspection(action_type, params, runner=None):
    """Run one read-only inspection, converting command failures safely."""
    if action_type not in _HANDLERS:
        raise UnknownActionError(
            f"Unsupported inspection action: {action_type!r}"
        )

    try:
        return _HANDLERS[action_type](params, runner=runner)
    except CommandError as exc:
        return _unavailable(action_type, exc)
