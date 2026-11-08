"""Typed models and shared errors for the defensive-actions subsystem.

Only the standard library is used: the project's core dependencies stay
``Flask + scikit-learn + joblib`` and the RAG stack stays optional.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

ACTION_TTL_SECONDS = 15 * 60
APPROVAL_TTL_SECONDS = 5 * 60

RISK_LEVELS = ("low", "medium", "high")

ACTION_STATUSES = (
    "pending", "executing", "executed", "cancelled", "expired", "unknown"
)


def utc_now():
    """Timezone-aware current time (never the deprecated ``utcnow``)."""
    return datetime.now(timezone.utc)


def iso(timestamp):
    """Render an epoch timestamp as an ISO-8601 UTC string."""
    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()


def new_id():
    """Unpredictable identifier for an action or approval record."""
    return secrets.token_hex(16)


def canonical_json(value):
    """Deterministic JSON used for hashing and signatures.

    ``ensure_ascii=True`` keeps the bytes identical regardless of the process
    locale, and sorted keys make parameter order irrelevant.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def params_hash(params):
    """SHA-256 of the canonical parameters."""
    return hashlib.sha256(canonical_json(params).encode("utf-8")).hexdigest()


def token_hash(token):
    """SHA-256 of an approval token; the raw token is never stored."""
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


class DefenseError(Exception):
    """Base class for every expected defense failure.

    ``error_category`` is a stable machine-readable string used by the API and
    the audit log. ``http_status`` keeps the Flask layer thin.
    """

    error_category = "defense_error"
    http_status = 400

    def __init__(self, message, action_id=None, error_category=None,
                 http_status=None):
        super().__init__(message)
        self.message = str(message)
        self.action_id = action_id
        if error_category is not None:
            self.error_category = error_category
        if http_status is not None:
            self.http_status = http_status

    def to_dict(self):
        payload = {
            "error": self.message,
            "error_category": self.error_category,
        }
        if self.action_id:
            payload["action_id"] = self.action_id
        return payload


class ActionError(DefenseError):
    """Generic action failure."""

    error_category = "action_error"


class UnknownActionError(ActionError):
    """The requested action type is not in the fixed registry."""

    error_category = "unknown_action"
    http_status = 400


class PolicyError(ActionError):
    """Parameters failed validation. The policy always fails closed."""

    error_category = "invalid_parameters"
    http_status = 400


class ActionNotFound(ActionError):
    """The action id is unknown (or the process restarted)."""

    error_category = "action_not_found"
    http_status = 404


class ActionExpired(ActionError):
    """The prepared action is older than its TTL."""

    error_category = "action_expired"
    http_status = 409


class ActionCancelled(ActionError):
    """The user cancelled this action."""

    error_category = "action_cancelled"
    http_status = 409


class DuplicateExecution(ActionError):
    """An action can be executed at most once."""

    error_category = "already_executed"
    http_status = 409


class ApprovalRequired(ActionError):
    """No approval exists for this action."""

    error_category = "approval_required"
    http_status = 409


class ApprovalInvalid(DefenseError):
    """The approval token, binding or confirmation is wrong."""

    error_category = "approval_invalid"
    http_status = 409


class ApprovalExpired(DefenseError):
    """The approval token expired before execution."""

    error_category = "approval_expired"
    http_status = 409


class ApprovalUsed(DefenseError):
    """The approval token was already consumed."""

    error_category = "approval_used"
    http_status = 409


class ElevationError(DefenseError):
    """The elevated execution adapter refused or failed."""

    error_category = "elevation_failed"
    http_status = 409


class ActionLimitExceeded(ActionError):
    """Too many prepared actions are retained in this process."""

    error_category = "action_limit_exceeded"
    http_status = 429


class ApprovalLimitExceeded(ActionError):
    """Too many approvals are retained in this process."""

    error_category = "approval_limit_exceeded"
    http_status = 429


class RateLimited(ActionError):
    """The caller is sending preparation/approval requests too quickly."""

    error_category = "rate_limited"
    http_status = 429


@dataclass
class ActionRequest:
    """A prepared action: validated, previewed, not yet executed."""

    action_id: str
    action_type: str
    params: dict
    target: str
    risk: str
    requires_admin: bool
    rollback_supported: bool
    created_at: float
    expires_at: float
    params_hash: str
    status: str = "pending"
    description: str = field(default="")

    def to_dict(self):
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "params": dict(self.params),
            "target": self.target,
            "risk": self.risk,
            "requires_admin": self.requires_admin,
            "rollback_supported": self.rollback_supported,
            "created_at": iso(self.created_at),
            "expires_at": iso(self.expires_at),
            "status": self.status,
        }


@dataclass
class ActionPreview:
    """Everything a human needs to decide whether to approve an action."""

    action_id: str
    action_type: str
    title: str
    target: str
    params: dict
    expected_effect: str
    risk: str
    requires_admin: bool
    rollback_supported: bool
    warnings: list
    existing_rule: str | None = None
    idempotent: bool = False
    created_at: float = 0.0
    expires_at: float = 0.0

    def to_dict(self):
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "title": self.title,
            "target": self.target,
            "params": dict(self.params),
            "expected_effect": self.expected_effect,
            "risk": self.risk,
            "requires_admin": self.requires_admin,
            "rollback_supported": self.rollback_supported,
            "warnings": list(self.warnings),
            "existing_rule": self.existing_rule,
            "idempotent": self.idempotent,
            "created_at": iso(self.created_at),
            "expires_at": iso(self.expires_at),
        }


@dataclass
class Approval:
    """Server-side approval record. The raw token is never stored."""

    approval_id: str
    action_id: str
    action_type: str
    params_hash: str
    issued_at: float
    expires_at: float
    token_hash: str
    used: bool = False

    def public_dict(self):
        # Deliberately excludes token_hash and any raw authorization material.
        return {
            "approval_id": self.approval_id,
            "action_id": self.action_id,
            "action_type": self.action_type,
            "issued_at": iso(self.issued_at),
            "expires_at": iso(self.expires_at),
            "single_use": True,
        }


@dataclass
class ExecutionResult:
    """Outcome of one execution attempt."""

    action_id: str
    action_type: str
    status: str  # success | failure | cancelled | rejected
    changed: bool
    approval: str  # granted | not_required | invalid | expired | used | cancelled
    elevation: str  # not_required | used | disabled | cancelled | failed
    error: str | None = None
    error_category: str | None = None
    detail: dict = field(default_factory=dict)
    rollback_available: bool = False
    rollback_status: str = "not_applicable"
    verified: bool | None = None
    duration_ms: int = 0

    def to_dict(self):
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "status": self.status,
            "changed": self.changed,
            "approval": self.approval,
            "elevation": self.elevation,
            "error": self.error,
            "error_category": self.error_category,
            "detail": dict(self.detail),
            "rollback_available": self.rollback_available,
            "rollback_status": self.rollback_status,
            "verified": self.verified,
            "duration_ms": self.duration_ms,
        }


@dataclass
class AuditEvent:
    """One append-only audit record.

    The field list is intentionally small and fixed: no tokens, passwords,
    command lines or free-form notes are recorded.
    """

    event_type: str  # preview | approval | execution | cancellation | rollback
    action_id: str
    action_type: str
    target: str
    params_summary: dict
    approval: str
    outcome: str
    error_category: str | None = None
    elevation: str = "not_required"
    rollback_available: bool = False
    rollback_status: str = "not_applicable"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return {
            "timestamp": iso(self.timestamp),
            "event_type": self.event_type,
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target": self.target,
            "params_summary": dict(self.params_summary),
            "approval": self.approval,
            "outcome": self.outcome,
            "error_category": self.error_category,
            "elevation": self.elevation,
            "rollback_available": bool(self.rollback_available),
            "rollback_status": self.rollback_status,
        }
