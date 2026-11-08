"""Application-facing facade for the defensive-actions subsystem.

``app.py`` talks only to :class:`DefenseService`; it never imports the Windows
modules, the approval stores or the executor directly. This keeps the Flask
routes thin and lets tests build a fully isolated service with a temporary
directory, a fake clock and mocked Windows runners.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from defense.approvals import ActionStore, ApprovalStore, RateLimiter
from defense.audit import DEFAULT_READ_EVENTS, MAX_READ_BYTES, AuditLog
from defense.executor import Executor
from defense.models import RateLimited
from defense.registry import list_specs
from defense.windows.elevated import ElevationAdapter, defense_base_dir
from defense.windows.firewall import RuleRegistry

LIMITATIONS = [
    "Process termination is not implemented in this version.",
    "Defender, antivirus and Windows Firewall are never disabled.",
    "Automatic blocking of addresses is not implemented: every state-changing "
    "action needs a separate human approval.",
    "The elevated adapter is disabled by default. It also refuses to run "
    "unless the helper is installed in an administrator-protected root "
    "(CYBERGUARD_DEFENSE_HELPER_ROOT) with a verified ACL; a repository "
    "checkout is not trusted.",
    "Rule expiry is recorded and used by rollback/audit, but Windows Firewall "
    "has no native TTL: an expired CyberGuard rule stays until it is removed. "
    "lifetime_minutes does NOT remove the rule automatically.",
    "The audit log is append-only through the application but is a local "
    "user-owned file; a local administrator or same-user process can alter it.",
    "The HMAC requests protect the hand-off protocol, not the whole host. A "
    "process running as the same Windows user can still tamper with "
    "CyberGuard's user-owned data directory.",
    "A timeout is reported as execution_unknown; it is not proof that the "
    "helper stopped, and the action is not retried automatically.",
]


class DefenseService:
    def __init__(self, base_dir=None, clock=time.time, elevation=None,
                 inspection_runner=None, firewall_runner=None,
                 audit=None, rules=None, actions=None, approvals=None):
        base = Path(base_dir) if base_dir is not None else defense_base_dir()
        self.base_dir = base
        self.clock = clock

        self.audit = audit or AuditLog(base / "audit.jsonl", clock=clock)
        self.rules = rules or RuleRegistry(base / "rules.json", clock=clock)
        self.actions = actions or ActionStore(clock=clock)
        self.approvals = approvals or ApprovalStore(clock=clock)
        self.rate_limiter = RateLimiter(clock=clock)
        self.elevation = elevation or ElevationAdapter(
            base_dir=base, clock=clock,
            firewall_runner=firewall_runner,
        )

        self.executor = Executor(
            actions=self.actions,
            approvals=self.approvals,
            audit=self.audit,
            rules=self.rules,
            elevation=self.elevation,
            clock=clock,
            inspection_runner=inspection_runner,
            firewall_runner=firewall_runner,
        )

    def status(self):
        return {
            "available": True,
            "platform": "windows" if sys.platform == "win32" else "other",
            "elevation": self.elevation.status(),
            "actions": [spec.public_dict() for spec in list_specs()],
            "rules_active": len(self.rules.list_active()),
            "rules_registry": self.rules.health(),
            "audit": {
                "events": self.audit.count(),
                "read_only": True,
                "health": self.audit.health(),
            },
            "limitations": list(LIMITATIONS),
        }

    def _check_rate(self, key):
        if not self.rate_limiter.allow(key):
            raise RateLimited(
                "Too many defensive-action requests. Wait a minute and try "
                "again."
            )

    def inspect(self, action_type, params=None):
        return self.executor.inspect(action_type, params or {})

    def preview(self, action_type, params=None):
        self._check_rate("preview")
        action, preview = self.executor.preview(action_type, params or {})
        return {"action": action.to_dict(), "preview": preview.to_dict()}

    def approve(self, action_id, confirm):
        self._check_rate("approve")
        return self.executor.approve(action_id, confirm)

    def execute(self, action_id, approval_token=None):
        self._check_rate("execute")
        return self.executor.execute(action_id, approval_token).to_dict()

    def cancel(self, action_id):
        return self.executor.cancel(action_id)

    def prepare_rollback(self, action_id):
        return self.executor.prepare_rollback(action_id)

    def audit_events(self, limit=DEFAULT_READ_EVENTS):
        events = self.audit.read(limit)
        total = self.audit.count()
        return {
            "events": events,
            "count": total,
            "limit": limit,
            "truncated": total > len(events),
            "read_limit_bytes": MAX_READ_BYTES,
        }
