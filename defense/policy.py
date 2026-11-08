"""Fail-closed parameter validation for defensive actions.

Nothing in this module executes anything. It only turns untrusted request data
into a small, canonical, explicitly-typed parameter dictionary, or raises
:class:`~defense.models.PolicyError`.

Rules that keep the blast radius small
--------------------------------------
* Only the exact keys a handler understands are accepted; extras are rejected.
* Addresses are parsed by :mod:`ipaddress`; unspecified, multicast, loopback,
  prefix-0 and very broad networks are refused.
* Ports, protocols, profiles, directions and lifetimes are bounded.
* A firewall rule name is always derived server-side from the canonical
  parameters and always carries the ``CyberGuard-`` prefix. A caller can never
  choose an arbitrary rule name.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

from defense.models import PolicyError, canonical_json

RULE_PREFIX = "CyberGuard-"
RULE_NAME_RE = re.compile(r"^CyberGuard-[A-Za-z0-9._-]{1,96}$")

PROTOCOLS = ("tcp", "udp", "any")
DIRECTIONS = ("inbound", "outbound")
PROFILES = ("any", "domain", "private", "public")
NETWORK_PROTOCOLS = ("all", "tcp", "udp")

MIN_LIFETIME_MINUTES = 1
MAX_LIFETIME_MINUTES = 24 * 60
DEFAULT_LIFETIME_MINUTES = 60

MAX_LIMIT = 500
DEFAULT_LIMIT = 100

MAX_TITLE_CHARS = 120
MAX_NOTES_CHARS = 2000
MAX_DESCRIPTION_CHARS = 200

# Broad networks are refused so a typo cannot block the whole internet.
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 16

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_DESCRIPTION_RE = re.compile(r"^[A-Za-z0-9 .,;:_()/@+\-]{1,200}$")

READ_ONLY_ACTIONS = (
    "list_processes",
    "list_network_connections",
    "get_firewall_status",
    "generate_incident_report",
    "preview_firewall_block_rule",
)

STATE_CHANGING_ACTIONS = (
    "create_firewall_block_rule",
    "remove_cyberguard_firewall_rule",
)

FIREWALL_ACTIONS = STATE_CHANGING_ACTIONS


def _require_dict(params):
    if not isinstance(params, dict):
        raise PolicyError("params must be a JSON object.")
    return params


def _only_keys(params, allowed):
    unexpected = sorted(set(params) - set(allowed))
    if unexpected:
        raise PolicyError(
            "Unexpected parameter(s): " + ", ".join(unexpected) + "."
        )


def _clean_text(value, name, limit, default=None):
    if value is None:
        return default
    if not isinstance(value, str):
        raise PolicyError(f"{name} must be a string.")
    if _CONTROL_RE.search(value):
        raise PolicyError(f"{name} must not contain control characters.")
    value = value.strip()
    if not value:
        raise PolicyError(f"{name} must not be empty.")
    if len(value) > limit:
        raise PolicyError(f"{name} must be at most {limit} characters.")
    return value


def _parse_int(value, name, minimum, maximum, default=None):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{name} must be an integer.")
    if not minimum <= value <= maximum:
        raise PolicyError(
            f"{name} must be between {minimum} and {maximum}."
        )
    return value


def parse_port(value, name):
    """Validate one port or ``start-end`` range; return a canonical string."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise PolicyError(f"{name} must be a port number or range.")

    if isinstance(value, int):
        start = end = value
    elif isinstance(value, str):
        match = re.fullmatch(r"(\d{1,5})(?:\s*-\s*(\d{1,5}))?", value.strip())
        if not match:
            raise PolicyError(
                f"{name} must be a port number (1-65535) or range 'a-b'."
            )
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else start
    else:
        raise PolicyError(f"{name} must be a port number or range.")

    if not 1 <= start <= 65535 or not 1 <= end <= 65535:
        raise PolicyError(f"{name} must be between 1 and 65535.")
    if start > end:
        raise PolicyError(f"{name} range start must not exceed its end.")

    return str(start) if start == end else f"{start}-{end}"


def parse_network(value):
    """Validate an IPv4/IPv6 host or CIDR; return a canonical network string."""
    if not isinstance(value, str):
        raise PolicyError(
            "remote_address must be an IPv4 or IPv6 address or CIDR block."
        )
    text = value.strip()
    if not text:
        raise PolicyError("remote_address must not be empty.")
    if len(text) > 64:
        raise PolicyError("remote_address is too long.")

    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise PolicyError(
            "remote_address must be a valid IPv4 or IPv6 address or CIDR "
            "block."
        ) from None

    if network.is_unspecified:
        raise PolicyError("remote_address must not be an unspecified address.")
    if network.is_multicast:
        raise PolicyError("remote_address must not be a multicast address.")
    if network.is_loopback:
        raise PolicyError("remote_address must not be a loopback address.")

    minimum = MIN_PREFIX_V4 if network.version == 4 else MIN_PREFIX_V6
    if network.prefixlen < minimum:
        raise PolicyError(
            f"remote_address is too broad; use a prefix of at least "
            f"/{minimum} for IPv{network.version}."
        )

    return str(network)


def display_address(network_text):
    """Human-friendly address: a host network is shown without ``/32``."""
    try:
        network = ipaddress.ip_network(network_text, strict=False)
    except ValueError:
        return str(network_text)
    if network.num_addresses == 1:
        return str(network.network_address)
    return str(network)


def _validate_firewall_block(params):
    params = _require_dict(params)
    allowed = {
        "remote_address", "local_port", "remote_port", "protocol",
        "profile", "direction", "lifetime_minutes", "description",
    }
    _only_keys(params, allowed)

    remote_address = parse_network(params.get("remote_address"))

    protocol = params.get("protocol", "tcp")
    if not isinstance(protocol, str) or protocol.lower() not in PROTOCOLS:
        raise PolicyError(
            "protocol must be one of: " + ", ".join(PROTOCOLS) + "."
        )
    protocol = protocol.lower()

    direction = params.get("direction", "inbound")
    if not isinstance(direction, str) or direction.lower() not in DIRECTIONS:
        raise PolicyError(
            "direction must be one of: " + ", ".join(DIRECTIONS) + "."
        )
    direction = direction.lower()

    profile = params.get("profile", "any")
    if not isinstance(profile, str) or profile.lower() not in PROFILES:
        raise PolicyError(
            "profile must be one of: " + ", ".join(PROFILES) + "."
        )
    profile = profile.lower()

    local_port = parse_port(params.get("local_port"), "local_port")
    remote_port = parse_port(params.get("remote_port"), "remote_port")

    if protocol == "any" and (local_port or remote_port):
        raise PolicyError(
            "A protocol of 'any' cannot be combined with an explicit port."
        )

    lifetime = _parse_int(
        params.get("lifetime_minutes"),
        "lifetime_minutes",
        MIN_LIFETIME_MINUTES,
        MAX_LIFETIME_MINUTES,
        default=DEFAULT_LIFETIME_MINUTES,
    )

    description = params.get("description")
    if description is not None:
        if not isinstance(description, str):
            raise PolicyError("description must be a string.")
        description = description.strip()
        if description and not _DESCRIPTION_RE.fullmatch(description):
            raise PolicyError(
                "description may only contain letters, digits, spaces and "
                ".,;:_()/@+- (max 200 characters)."
            )
        if not description:
            description = None

    canonical = {
        "remote_address": remote_address,
        "protocol": protocol,
        "direction": direction,
        "profile": profile,
        "local_port": local_port,
        "remote_port": remote_port,
        "lifetime_minutes": lifetime,
        "description": description,
    }

    if not (local_port or remote_port or remote_address):
        raise PolicyError("The rule would be unrestricted; refusing it.")

    return canonical


def rule_name_for(params):
    """Derive the CyberGuard-owned rule name from canonical parameters.

    ``lifetime_minutes`` and ``description`` are intentionally excluded so that
    repeating the same block is idempotent instead of creating a second rule.
    """
    identity = {
        "remote_address": params["remote_address"],
        "protocol": params["protocol"],
        "direction": params["direction"],
        "profile": params["profile"],
        "local_port": params["local_port"],
        "remote_port": params["remote_port"],
    }
    digest = hashlib.sha256(
        canonical_json(identity).encode("utf-8")
    ).hexdigest()[:10]
    short = "In" if params["direction"] == "inbound" else "Out"
    return (
        f"{RULE_PREFIX}Block-{short}-{params['protocol'].upper()}-{digest}"
    )


def firewall_target(params):
    """Describe the exact firewall effect in one safe line."""
    direction = "inbound" if params["direction"] == "inbound" else "outbound"
    parts = [
        f"Windows Firewall: block {direction} {params['protocol'].upper()}",
        f"from {display_address(params['remote_address'])}",
    ]
    if params.get("local_port"):
        parts.append(f"to local port {params['local_port']}")
    if params.get("remote_port"):
        parts.append(f"remote port {params['remote_port']}")
    parts.append(f"on the {params['profile']} profile")
    return " ".join(parts)


def _validate_remove(params):
    params = _require_dict(params)
    _only_keys(params, {"rule_name"})
    rule_name = params.get("rule_name")
    if not isinstance(rule_name, str):
        raise PolicyError("rule_name must be a string.")
    rule_name = rule_name.strip()
    if not RULE_NAME_RE.fullmatch(rule_name):
        raise PolicyError(
            "rule_name must be a CyberGuard-owned rule name "
            "(prefix 'CyberGuard-')."
        )
    return {"rule_name": rule_name}


def _validate_processes(params):
    params = _require_dict(params)
    _only_keys(params, {"limit"})
    return {
        "limit": _parse_int(
            params.get("limit"), "limit", 1, MAX_LIMIT, default=DEFAULT_LIMIT
        )
    }


def _validate_connections(params):
    params = _require_dict(params)
    _only_keys(params, {"limit", "protocol"})
    protocol = params.get("protocol", "all")
    if not isinstance(protocol, str) or protocol.lower() not in NETWORK_PROTOCOLS:
        raise PolicyError(
            "protocol must be one of: " + ", ".join(NETWORK_PROTOCOLS) + "."
        )
    return {
        "limit": _parse_int(
            params.get("limit"), "limit", 1, MAX_LIMIT, default=DEFAULT_LIMIT
        ),
        "protocol": protocol.lower(),
    }


def _validate_firewall_status(params):
    params = _require_dict(params)
    _only_keys(params, {"include_raw"})
    include_raw = params.get("include_raw", True)
    if not isinstance(include_raw, bool):
        raise PolicyError("include_raw must be a boolean.")
    return {"include_raw": include_raw}


def _validate_incident_report(params):
    params = _require_dict(params)
    _only_keys(params, {"title", "notes", "threat_type", "risk"})

    risk = params.get("risk", "UNKNOWN")
    if not isinstance(risk, str) or risk.upper() not in (
        "LOW", "MEDIUM", "HIGH", "UNKNOWN"
    ):
        raise PolicyError("risk must be LOW, MEDIUM, HIGH or UNKNOWN.")

    return {
        "title": _clean_text(
            params.get("title"), "title", MAX_TITLE_CHARS,
            default="CyberGuard incident report",
        ),
        "notes": _clean_text(
            params.get("notes"), "notes", MAX_NOTES_CHARS, default=None
        ),
        "threat_type": _clean_text(
            params.get("threat_type"), "threat_type", 60, default="Unknown"
        ),
        "risk": risk.upper(),
    }


_VALIDATORS = {
    "list_processes": _validate_processes,
    "list_network_connections": _validate_connections,
    "get_firewall_status": _validate_firewall_status,
    "generate_incident_report": _validate_incident_report,
    "preview_firewall_block_rule": _validate_firewall_block,
    "create_firewall_block_rule": _validate_firewall_block,
    "remove_cyberguard_firewall_rule": _validate_remove,
}


def validate_action(action_type, params):
    """Validate and canonicalise parameters for ``action_type``.

    Unknown action types are rejected before any handler is reached.
    """
    if not isinstance(action_type, str) or not action_type:
        raise PolicyError("action_type must be a non-empty string.")

    validator = _VALIDATORS.get(action_type)
    if validator is None:
        from defense.models import UnknownActionError

        raise UnknownActionError(f"Unsupported action type: {action_type!r}")

    return validator(params)


def safe_params(action_type, params):
    """Whitelisted, bounded parameter summary safe to put in the audit log."""
    if not isinstance(params, dict):
        return {}
    allowed = {
        "remote_address", "local_port", "remote_port", "protocol",
        "profile", "direction", "lifetime_minutes", "rule_name", "limit",
        "title", "threat_type", "risk",
    }
    summary = {}
    for key in allowed:
        if key not in params:
            continue
        value = params[key]
        if value is None or isinstance(value, (bool, int, float)):
            summary[key] = value
        else:
            text = str(value)
            if len(text) > 120:
                text = text[:120] + "..."
            summary[key] = text
    return summary
