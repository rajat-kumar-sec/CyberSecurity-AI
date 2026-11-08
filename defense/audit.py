"""Append-only local audit history for defensive actions.

Design constraints
------------------
* One JSON object per line, appended to ``data/defense/audit.jsonl``.
* Only a fixed, whitelisted set of fields is written.  Approval tokens,
  passwords, authorization headers and free-form notes are never recorded.
* The file is bounded: when it exceeds ``max_bytes`` it is rotated to
  ``audit.jsonl.1`` (replacing the previous rotation).
* Paths are checked for symlinks/reparse points before reads and writes, and
  files are opened with explicit creation flags.

Honest integrity statement
--------------------------
This is an *application-level append-only* log.  It is **not** tamper-proof and
it has no cryptographic chain.  A local administrator, the owning user, or
malware running as that user can edit or delete the file outside CyberGuard.
Windows Event Log integration is intentionally not attempted here; it would
need its own elevated, independently-tested deployment.
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
import time
from pathlib import Path

from defense.models import AuditEvent, iso
from defense.policy import safe_params
from defense.windows import security

MAX_READ_EVENTS = 200
DEFAULT_READ_EVENTS = 50
MAX_READ_BYTES = 1024 * 1024

_FORBIDDEN_KEY_RE = re.compile(
    r"(?i)(token|secret|password|passwd|authorization|api[_-]?key|credential)"
)

_AUDIT_KEYS = (
    "timestamp",
    "event_type",
    "action_id",
    "action_type",
    "target",
    "params_summary",
    "approval",
    "outcome",
    "error_category",
    "elevation",
    "rollback_available",
    "rollback_status",
)


def _safe_value(value, limit=200):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _finite(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def sanitize_event(event):
    """Project an event onto the fixed schema and drop sensitive keys."""
    summary = {}
    if isinstance(event.params_summary, dict):
        for key, value in event.params_summary.items():
            if not isinstance(key, str) or _FORBIDDEN_KEY_RE.search(key):
                continue
            if key not in {
                "remote_address", "local_port", "remote_port", "protocol",
                "profile", "direction", "lifetime_minutes", "rule_name",
                "limit", "title", "threat_type", "risk",
            }:
                continue
            summary[key] = _safe_value(value)

    if not _finite(event.timestamp):
        raise ValueError("The audit timestamp must be finite.")

    return {
        "timestamp": iso(event.timestamp),
        "event_type": _safe_value(event.event_type, 32),
        "action_id": _safe_value(event.action_id, 64),
        "action_type": _safe_value(event.action_type, 64),
        "target": _safe_value(event.target, 240),
        "params_summary": summary,
        "approval": _safe_value(event.approval, 32),
        "outcome": _safe_value(event.outcome, 32),
        "error_category": (
            None if event.error_category is None
            else _safe_value(event.error_category, 64)
        ),
        "elevation": _safe_value(event.elevation, 32),
        "rollback_available": bool(event.rollback_available),
        "rollback_status": _safe_value(event.rollback_status, 32),
    }


class AuditLog:
    """Thread-safe append-only JSONL audit log."""

    def __init__(self, path, max_bytes=2 * 1024 * 1024, clock=time.time):
        self.path = Path(path)
        self.max_bytes = max(1, int(max_bytes))
        self._lock = threading.Lock()
        self._clock = clock
        self._last_error = None

    @property
    def rotated_path(self):
        return self.path.with_name(self.path.name + ".1")

    def _assert_safe(self, path, kind="file", allow_missing=True):
        try:
            return security.assert_safe_path(
                path, kind=kind,
                max_bytes=max(self.max_bytes * 4, MAX_READ_BYTES),
                allow_missing=allow_missing,
            )
        except security.SecurityError as exc:
            self._last_error = exc.message
            raise

    def _ensure_dir(self):
        try:
            security.secure_mkdir(self.path.parent)
        except security.SecurityError as exc:
            self._last_error = exc.message
            raise

    def _rotate_if_needed(self):
        try:
            details = self._assert_safe(self.path, allow_missing=True)
            if details is None:
                return
            if details.st_size < self.max_bytes:
                return
            # ``os.replace`` replaces the directory entry rather than
            # following a pre-created symlink at the rotated name.
            os.replace(self.path, self.rotated_path)
        except (OSError, security.SecurityError):
            # Rotation is best effort; an append is safer than losing history.
            pass

    def record(self, event):
        """Append one :class:`AuditEvent`; return the sanitized dict."""
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent")

        data = sanitize_event(event)
        line = json.dumps(
            data, ensure_ascii=True, sort_keys=True, allow_nan=False
        ) + "\n"
        encoded = line.encode("utf-8")

        with self._lock:
            self._ensure_dir()
            self._assert_safe(self.path, allow_missing=True)
            self._rotate_if_needed()
            flags = (
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | getattr(os, "O_BINARY", 0)
            )
            descriptor = os.open(self.path, flags, 0o600)
            try:
                os.write(descriptor, encoded)
                try:
                    os.fsync(descriptor)
                except OSError:
                    pass
            finally:
                os.close(descriptor)

        return data

    def record_action(self, *, event_type, action, params_summary=None,
                      approval, outcome, error_category=None,
                      elevation="not_required", rollback_available=False,
                      rollback_status="not_applicable"):
        """Convenience wrapper used by the executor."""
        event = AuditEvent(
            event_type=event_type,
            action_id=getattr(action, "action_id", ""),
            action_type=getattr(action, "action_type", ""),
            target=getattr(action, "target", ""),
            params_summary=(
                safe_params(getattr(action, "action_type", ""),
                            getattr(action, "params", {}))
                if params_summary is None else params_summary
            ),
            approval=approval,
            outcome=outcome,
            error_category=error_category,
            elevation=elevation,
            rollback_available=rollback_available,
            rollback_status=rollback_status,
            timestamp=float(self._clock()),
        )
        return self.record(event)

    def _read_lines(self, path=None):
        path = self.path if path is None else Path(path)
        if not path.exists():
            return []
        try:
            self._assert_safe(path, allow_missing=True)
            size = path.stat().st_size
            with open(path, "rb") as handle:
                if size > MAX_READ_BYTES:
                    handle.seek(size - MAX_READ_BYTES)
                    handle.readline()  # drop the partial first line
                payload = handle.read()
        except (OSError, security.SecurityError):
            return []

        text = payload.decode("utf-8", "replace")
        return [line for line in text.splitlines() if line.strip()]

    def read(self, limit=DEFAULT_READ_EVENTS):
        """Return newest-first events; malformed lines are skipped."""
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = DEFAULT_READ_EVENTS
        limit = max(1, min(limit, MAX_READ_EVENTS))

        # Read the rotated (older) file first, then the current file, and
        # reverse the combined list so the newest event is first.
        lines = self._read_lines(self.rotated_path)
        lines.extend(self._read_lines(self.path))

        events = []
        for line in reversed(lines):
            try:
                item = json.loads(
                    line,
                    parse_constant=lambda value: (_ for _ in ()).throw(
                        ValueError(f"non-finite {value}")
                    ),
                )
            except (ValueError, TypeError):
                continue
            if not isinstance(item, dict):
                continue
            events.append({key: item.get(key) for key in _AUDIT_KEYS})
            if len(events) >= limit:
                break
        return events

    def _count_path(self, path):
        if not path.exists():
            return 0
        try:
            self._assert_safe(path, allow_missing=True)
            count = 0
            last_byte = b"\n"
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    count += chunk.count(b"\n")
                    last_byte = chunk[-1:]
            if last_byte not in (b"", b"\n"):
                count += 1
            return count
        except (OSError, security.SecurityError):
            return 0

    def count(self):
        """Total line count across the current and one rotated file.

        Unlike the previous implementation this does not silently stop at the
        last 1 MiB; it streams the files in bounded chunks.
        """
        return self._count_path(self.rotated_path) + self._count_path(self.path)

    def health(self):
        return {
            "path_configured": bool(str(self.path)),
            "rotated": self.rotated_path.exists(),
            "max_bytes": self.max_bytes,
            "last_error": self._last_error,
        }
