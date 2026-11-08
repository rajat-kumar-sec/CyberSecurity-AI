"""Fixed action registry.

Only the actions listed here can ever be prepared. The registry is data, not a
plugin system: there is no dynamic import, no entry-point discovery and no way
for a request to register a new action.

The list is intentionally short. Process termination is *not* supported in this
version, and neither is disabling Windows Defender, the firewall or antivirus.
"""

from __future__ import annotations

from dataclasses import dataclass

from defense import policy
from defense.models import UnknownActionError


def _effect(text, warnings=None):
    return {"expected_effect": text, "warnings": list(warnings or [])}


def _processes_preview(params, rules=None):
    return {
        "title": "List running processes",
        "target": "Local Windows process table",
        **_effect(
            "Reads the process list with a fixed 'tasklist' invocation. "
            "No process is started, stopped or modified.",
        ),
    }


def _connections_preview(params, rules=None):
    return {
        "title": "List active network connections",
        "target": "Local Windows TCP/UDP connection table",
        **_effect(
            "Reads connections with a fixed 'netstat -ano' invocation. "
            "No connection is opened, closed or modified.",
        ),
    }


def _firewall_status_preview(params, rules=None):
    return {
        "title": "Show Windows Firewall status",
        "target": "Windows Firewall profiles",
        **_effect(
            "Reads the firewall profile state with a fixed 'netsh' "
            "invocation. No setting is changed.",
        ),
    }


def _report_preview(params, rules=None):
    return {
        "title": params.get("title") or "CyberGuard incident report",
        "target": "In-memory incident report",
        **_effect(
            "Builds a structured report in memory from the supplied fields. "
            "No file is written and no system state is changed.",
        ),
    }


def _block_preview(params, rules=None):
    rule_name = policy.rule_name_for(params)
    existing = rules.get(rule_name) if rules is not None else None

    warnings = []
    if params["direction"] == "outbound":
        warnings.append(
            "Blocking outbound traffic can interrupt connectivity for the "
            "target; prefer inbound unless you are sure."
        )
    if params["protocol"] == "any":
        warnings.append(
            "This blocks every protocol (TCP, UDP and others)."
        )
    if params["profile"] == "any":
        warnings.append(
            "The rule applies to the domain, private and public profiles."
        )

    return {
        "title": "Create a Windows Firewall block rule",
        "target": policy.firewall_target(params),
        **_effect(
            "Creates a single inbound/outbound block rule owned by "
            f"CyberGuard (name '{rule_name}'). Repeating the same request "
            "reuses the existing rule instead of creating a duplicate. "
            "The rule is not removed automatically when it expires; use "
            "remove_cyberguard_firewall_rule to delete it.",
            warnings,
        ),
        "existing_rule": existing.get("rule_name") if existing else None,
        "idempotent": existing is not None,
        "rule_name": rule_name,
    }


def _preview_block_preview(params, rules=None):
    data = _block_preview(params, rules)
    data["title"] = "Preview a Windows Firewall block rule"
    data["expected_effect"] = (
        "Read-only preview. It reports the exact rule that "
        "create_firewall_block_rule would create, but creates nothing."
    )
    return data


def _remove_preview(params, rules=None):
    rule_name = params["rule_name"]
    record = rules.get(rule_name) if rules is not None else None
    warnings = [
        "Only rules recorded as CyberGuard-owned can be removed. "
        "Unrelated firewall rules are never touched."
    ]
    if record is None:
        warnings.append(
            "This rule is not in CyberGuard's ownership record; the action "
            "will be refused."
        )
    return {
        "title": "Remove a CyberGuard-owned firewall rule",
        "target": f"Windows Firewall rule {rule_name}",
        **_effect(
            "Deletes exactly one rule whose name starts with 'CyberGuard-' "
            "and which CyberGuard created and recorded. The recorded "
            "parameters are kept so the rule can be re-created (rollback), "
            "but rollback is a separate action that needs its own approval.",
            warnings,
        ),
        "existing_rule": record.get("rule_name") if record else None,
        "idempotent": record is None,
    }


@dataclass(frozen=True)
class ActionSpec:
    """Static description of one supported action."""

    action_type: str
    title: str
    description: str
    risk: str
    requires_admin: bool
    rollback_supported: bool
    read_only: bool
    preview_builder: object

    def public_dict(self):
        return {
            "action_type": self.action_type,
            "title": self.title,
            "description": self.description,
            "risk": self.risk,
            "requires_admin": self.requires_admin,
            "rollback_supported": self.rollback_supported,
            "read_only": self.read_only,
        }


REGISTRY = {
    "list_processes": ActionSpec(
        action_type="list_processes",
        title="List running processes",
        description="Read-only process list.",
        risk="low",
        requires_admin=False,
        rollback_supported=False,
        read_only=True,
        preview_builder=_processes_preview,
    ),
    "list_network_connections": ActionSpec(
        action_type="list_network_connections",
        title="List active network connections",
        description="Read-only TCP/UDP connection list with owning PID.",
        risk="low",
        requires_admin=False,
        rollback_supported=False,
        read_only=True,
        preview_builder=_connections_preview,
    ),
    "get_firewall_status": ActionSpec(
        action_type="get_firewall_status",
        title="Show Windows Firewall status",
        description="Read-only firewall profile state.",
        risk="low",
        requires_admin=False,
        rollback_supported=False,
        read_only=True,
        preview_builder=_firewall_status_preview,
    ),
    "generate_incident_report": ActionSpec(
        action_type="generate_incident_report",
        title="Generate an incident report",
        description="Builds an in-memory incident report; writes nothing.",
        risk="low",
        requires_admin=False,
        rollback_supported=False,
        read_only=True,
        preview_builder=_report_preview,
    ),
    "preview_firewall_block_rule": ActionSpec(
        action_type="preview_firewall_block_rule",
        title="Preview a firewall block rule",
        description="Read-only preview of a would-be block rule.",
        risk="low",
        requires_admin=False,
        rollback_supported=False,
        read_only=True,
        preview_builder=_preview_block_preview,
    ),
    "create_firewall_block_rule": ActionSpec(
        action_type="create_firewall_block_rule",
        title="Create a firewall block rule",
        description="Creates one CyberGuard-owned block rule.",
        risk="medium",
        requires_admin=True,
        rollback_supported=True,
        read_only=False,
        preview_builder=_block_preview,
    ),
    "remove_cyberguard_firewall_rule": ActionSpec(
        action_type="remove_cyberguard_firewall_rule",
        title="Remove a CyberGuard-owned firewall rule",
        description="Deletes one positively identified CyberGuard rule.",
        risk="medium",
        requires_admin=True,
        rollback_supported=True,
        read_only=False,
        preview_builder=_remove_preview,
    ),
}


def get_spec(action_type):
    """Return the spec for a known action or raise ``UnknownActionError``."""
    if not isinstance(action_type, str) or action_type not in REGISTRY:
        raise UnknownActionError(
            f"Unsupported action type: {action_type!r}. "
            "Only registered actions are allowed."
        )
    return REGISTRY[action_type]


def list_specs():
    """Every supported action, in a stable order."""
    return [REGISTRY[key] for key in REGISTRY]
