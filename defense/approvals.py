"""In-memory action and approval stores.

Both stores are deliberately process-local: a restart invalidates every
prepared action and every approval, which is the safe direction (fail closed).
Nothing here is written to disk, so a token cannot leak through a state file.

An approval is bound to the action id, action type, canonical parameter hash
and expiry. It is single-use: :meth:`ApprovalStore.consume` marks it used
*before* the executor can run anything, so a replay or a concurrent duplicate
is rejected even if execution later fails.
"""

from __future__ import annotations

import hmac
import re
import secrets
import threading
import time

from defense.models import (
    APPROVAL_TTL_SECONDS,
    ActionCancelled,
    ActionError,
    ActionExpired,
    ActionLimitExceeded,
    ActionNotFound,
    Approval,
    ApprovalExpired,
    ApprovalInvalid,
    ApprovalLimitExceeded,
    ApprovalRequired,
    ApprovalUsed,
    DuplicateExecution,
    token_hash,
)

_ACTION_ID_RE = re.compile(r"^[a-f0-9]{32}$")
_MAX_TOKEN_CHARS = 200

MAX_ACTIONS = 200
MAX_APPROVALS = 200
DEFAULT_RATE_LIMIT = 60
DEFAULT_RATE_WINDOW_SECONDS = 60.0


class ActionStore:
    """Prepared actions awaiting approval or execution."""

    def __init__(self, clock=time.time, max_items=MAX_ACTIONS):
        self._items = {}
        self._lock = threading.RLock()
        self._clock = clock
        self._max_items = max(1, int(max_items))

    def add(self, action):
        with self._lock:
            self.prune()
            if len(self._items) >= self._max_items:
                # At capacity: finished records are disposable, pending ones
                # are not.  This keeps the limit meaningful without rejecting
                # a new preview just because old finished actions are retained.
                self._drop_finished_locked()
            if len(self._items) >= self._max_items:
                raise ActionLimitExceeded(
                    "Too many prepared actions are pending. Wait for them to "
                    "expire or cancel one before preparing another."
                )
            self._items[action.action_id] = action
            return action

    def _drop_finished_locked(self):
        finished = [
            action_id for action_id, item in self._items.items()
            if item.status in (
                "executed", "cancelled", "expired", "unknown"
            )
        ]
        for action_id in finished:
            self._items.pop(action_id, None)
        return len(finished)

    def _lookup(self, action_id):
        if not isinstance(action_id, str) or not _ACTION_ID_RE.fullmatch(
            action_id
        ):
            raise ActionNotFound("Unknown or malformed action id.")
        action = self._items.get(action_id)
        if action is None:
            raise ActionNotFound(
                "Unknown action id; it may have expired or the server may "
                "have restarted."
            )
        return action

    def get(self, action_id):
        """Return a pending, unexpired action or raise a precise error."""
        with self._lock:
            action = self._lookup(action_id)

            if action.status == "cancelled":
                raise ActionCancelled(
                    "This action was cancelled.", action_id=action.action_id
                )
            if action.status == "executed":
                raise DuplicateExecution(
                    "This action has already been executed.",
                    action_id=action.action_id,
                )
            if action.status == "executing":
                raise DuplicateExecution(
                    "This action is already executing.",
                    action_id=action.action_id,
                )
            if action.status == "unknown":
                raise DuplicateExecution(
                    "This action has an unresolved execution outcome and "
                    "cannot be retried. Reconcile the firewall state first.",
                    action_id=action.action_id,
                )
            if action.status == "expired" or self._clock() > action.expires_at:
                action.status = "expired"
                raise ActionExpired(
                    "This action expired before it was executed. Prepare it "
                    "again.",
                    action_id=action.action_id,
                )
            return action

    def get_any(self, action_id):
        """Return an action regardless of status (used for rollback lookup)."""
        with self._lock:
            return self._lookup(action_id)

    def claim(self, action_id):
        """Atomically move a pending action to ``executing``.

        This is the duplicate-execution guard: only one caller can win the
        transition, and the approval is consumed by the caller separately.
        """
        with self._lock:
            action = self.get(action_id)
            action.status = "executing"
            return action

    def finish(self, action_id, outcome="executed"):
        """Record the final execution state.

        An uncertain elevated outcome is stored as ``unknown`` rather than
        ``executed`` so the API never claims success and a duplicate execution
        is still refused.
        """
        with self._lock:
            action = self._lookup(action_id)
            if action.status == "executing":
                if outcome in ("execution_unknown", "unknown"):
                    action.status = "unknown"
                else:
                    action.status = "executed"
            return action

    def cancel(self, action_id):
        """Cancel a pending action. Cancelling twice is harmless."""
        with self._lock:
            action = self._lookup(action_id)
            if action.status == "executed":
                raise DuplicateExecution(
                    "This action has already been executed and cannot be "
                    "cancelled.",
                    action_id=action.action_id,
                )
            if action.status == "executing":
                raise ActionError(
                    "This action is already executing and can no longer be "
                    "cancelled.",
                    action_id=action.action_id,
                )
            if action.status != "cancelled":
                action.status = "cancelled"
            return action

    def prune(self, keep=MAX_ACTIONS):
        """Drop the oldest finished actions so the store stays bounded."""
        with self._lock:
            if len(self._items) <= keep:
                return 0
            finished = [
                item for item in self._items.values()
                if item.status in (
                    "executed", "cancelled", "expired", "unknown"
                )
            ]
            finished.sort(key=lambda item: item.created_at)
            removed = 0
            for item in finished:
                if len(self._items) <= keep:
                    break
                self._items.pop(item.action_id, None)
                removed += 1
            return removed

    def clear(self):
        with self._lock:
            self._items.clear()

    def __len__(self):
        with self._lock:
            return len(self._items)


class ApprovalStore:
    """Single-use, expiring approvals bound to one exact action."""

    def __init__(self, clock=time.time, ttl=APPROVAL_TTL_SECONDS,
                 max_items=MAX_APPROVALS):
        self._by_action = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._ttl = int(ttl)
        self._max_items = max(1, int(max_items))

    def _prune_locked(self):
        now = float(self._clock())
        expired = [
            action_id for action_id, record in self._by_action.items()
            if record.used or now > record.expires_at
        ]
        for action_id in expired:
            self._by_action.pop(action_id, None)
        return len(expired)

    def prune(self):
        """Drop used and expired approvals; return the number removed."""
        with self._lock:
            return self._prune_locked()

    def issue(self, action):
        """Create a fresh approval, replacing any earlier one for the action.

        Returns ``(record, raw_token)``. The raw token is handed to the caller
        exactly once and only its SHA-256 hash is retained.
        """
        token = secrets.token_urlsafe(32)
        now = float(self._clock())
        record = Approval(
            approval_id=secrets.token_hex(16),
            action_id=action.action_id,
            action_type=action.action_type,
            params_hash=action.params_hash,
            issued_at=now,
            expires_at=now + self._ttl,
            token_hash=token_hash(token),
        )
        with self._lock:
            self._prune_locked()
            if len(self._by_action) >= self._max_items:
                raise ApprovalLimitExceeded(
                    "Too many approvals are pending. Wait for them to expire."
                )
            self._by_action[action.action_id] = record
        return record, token

    def consume(self, action_id, token, expected_params_hash=None,
                expected_action_type=None):
        """Validate and burn an approval.

        Order matters: structural token errors are reported before the
        single-use check, and the record is marked used before returning.
        """
        with self._lock:
            record = self._by_action.get(action_id)

            if record is None:
                raise ApprovalRequired(
                    "No approval exists for this action. Approve it first.",
                    action_id=action_id,
                )

            if not isinstance(token, str) or not token or len(
                token
            ) > _MAX_TOKEN_CHARS:
                raise ApprovalInvalid("A valid approval token is required.")

            if not hmac.compare_digest(
                record.token_hash, token_hash(token)
            ):
                raise ApprovalInvalid(
                    "The approval token is not valid for this action.",
                    action_id=action_id,
                )

            if record.used:
                raise ApprovalUsed(
                    "This approval was already used. Approve the action "
                    "again to run it again.",
                    action_id=action_id,
                )

            if float(self._clock()) > record.expires_at:
                raise ApprovalExpired(
                    "This approval expired. Approve the action again.",
                    action_id=action_id,
                )

            if expected_action_type is not None and (
                record.action_type != expected_action_type
            ):
                raise ApprovalInvalid(
                    "The approval is bound to a different action type.",
                    action_id=action_id,
                )

            if expected_params_hash is not None and (
                record.params_hash != expected_params_hash
            ):
                raise ApprovalInvalid(
                    "The parameters changed after approval; the approval is "
                    "no longer valid.",
                    action_id=action_id,
                )

            record.used = True
            return record

    def revoke(self, action_id):
        """Drop any approval for an action (used on cancellation)."""
        with self._lock:
            return self._by_action.pop(action_id, None) is not None

    def peek(self, action_id):
        with self._lock:
            return self._by_action.get(action_id)

    def clear(self):
        with self._lock:
            self._by_action.clear()

    def __len__(self):
        with self._lock:
            return len(self._by_action)


class RateLimiter:
    """Small in-process sliding-window limiter for preparation/approval calls.

    It is deliberately process-local and modest: it prevents a runaway browser
    loop from filling memory with prepared actions.  It is not an
    authentication boundary.
    """

    def __init__(self, clock=time.time, limit=DEFAULT_RATE_LIMIT,
                 window=DEFAULT_RATE_WINDOW_SECONDS):
        self._clock = clock
        self._limit = max(1, int(limit))
        self._window = max(1.0, float(window))
        self._events = {}
        self._lock = threading.Lock()

    def allow(self, key="default"):
        now = float(self._clock())
        cutoff = now - self._window
        with self._lock:
            events = [
                stamp for stamp in self._events.get(key, [])
                if stamp > cutoff
            ]
            if len(events) >= self._limit:
                self._events[key] = events
                return False
            events.append(now)
            self._events[key] = events
            return True

    def reset(self, key=None):
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)
