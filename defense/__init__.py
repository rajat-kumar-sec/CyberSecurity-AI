"""Windows defensive actions for CyberGuard AI (roadmap item 5, first version).

This package is deliberately separate from the threat analyzer: it never imports
``analyzer`` and the analyzer never imports it. The analyzer may *recommend* an
action; only this package can prepare, approve and execute one, and only after a
human explicitly approves that exact action.

Safety model
------------
* A fixed registry of action types. Unknown types are rejected, and no API
  accepts a command string, executable path, shell fragment or PowerShell text.
* All parameters are validated by :mod:`defense.policy` before preview and
  again immediately before execution.
* An approval is bound to the exact action id, type, canonical parameters and
  expiry, is single-use, and is stored only as a SHA-256 hash.
* State-changing actions run through a one-shot elevated helper. The helper
  independently revalidates a signed, expiring request, requires a persistent
  per-nonce consumption marker, and consumes the request once. The Flask
  process is never elevated.
* Everything is recorded in an append-only local audit log without tokens or
  other authorization material. The audit is application-level only: it is not
  tamper-proof against the owning user or a local administrator.

The Windows execution adapter is **disabled by default** and also refuses to run
unless the helper is installed in an administrator-protected root
(``CYBERGUARD_DEFENSE_HELPER_ROOT``) with a verified admin-only DACL and a
32-byte HMAC key with a verified restricted ACL. Read-only inspection, previews,
approvals and audit work without elevation.

Honest limits: CyberGuard does not implement OS-level user authentication and
cannot protect its user-owned data directory from malware running as the same
Windows user. A timeout is reported as ``execution_unknown`` rather than success
or failure.
"""

from defense.models import (
    ACTION_TTL_SECONDS,
    APPROVAL_TTL_SECONDS,
    ActionCancelled,
    ActionError,
    ActionExpired,
    ActionLimitExceeded,
    ActionNotFound,
    ActionPreview,
    ActionRequest,
    ApprovalExpired,
    ApprovalInvalid,
    ApprovalLimitExceeded,
    ApprovalRequired,
    ApprovalUsed,
    AuditEvent,
    DefenseError,
    DuplicateExecution,
    ExecutionResult,
    PolicyError,
    RateLimited,
    UnknownActionError,
)
from defense.registry import REGISTRY, ActionSpec, get_spec, list_specs

__all__ = [
    "ACTION_TTL_SECONDS",
    "APPROVAL_TTL_SECONDS",
    "REGISTRY",
    "ActionCancelled",
    "ActionError",
    "ActionExpired",
    "ActionLimitExceeded",
    "ActionNotFound",
    "ActionPreview",
    "ActionRequest",
    "ActionSpec",
    "ApprovalExpired",
    "ApprovalInvalid",
    "ApprovalLimitExceeded",
    "ApprovalRequired",
    "ApprovalUsed",
    "AuditEvent",
    "DefenseError",
    "DuplicateExecution",
    "ExecutionResult",
    "PolicyError",
    "RateLimited",
    "UnknownActionError",
    "get_spec",
    "list_specs",
]
