"""Fail-closed policy tests: addresses, ports, protocols and rule names."""

import pytest

from defense import policy
from defense.models import PolicyError, UnknownActionError


@pytest.mark.parametrize(
    "value, expected",
    [
        ("203.0.113.7", "203.0.113.7/32"),
        ("203.0.113.7/32", "203.0.113.7/32"),
        ("198.51.100.0/24", "198.51.100.0/24"),
        ("2001:db8::1", "2001:db8::1/128"),
        ("2001:db8::/32", "2001:db8::/32"),
    ],
)
def test_parse_network_accepts_unicast_v4_and_v6(value, expected):
    assert policy.parse_network(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "not-an-ip",
        "999.1.1.1",
        "1.2.3.4/33",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "127.0.0.1",
        "::1",
        "10.0.0.0/7",
        "2001:db8::/15",
        "1.2.3.4/32/24",
        None,
        1234,
        ["203.0.113.7"],
    ],
)
def test_parse_network_rejects_unsafe_or_malformed(value):
    with pytest.raises(PolicyError):
        policy.parse_network(value)


def test_display_address_drops_host_prefix():
    assert policy.display_address("203.0.113.7/32") == "203.0.113.7"
    assert policy.display_address("198.51.100.0/24") == "198.51.100.0/24"


@pytest.mark.parametrize(
    "value, expected",
    [
        (22, "22"),
        ("22", "22"),
        (" 22 ", "22"),
        ("20-25", "20-25"),
        ("20 - 25", "20-25"),
    ],
)
def test_parse_port_accepts_single_ports_and_ranges(value, expected):
    assert policy.parse_port(value, "local_port") == expected


@pytest.mark.parametrize(
    "value",
    [0, 65536, -1, "0", "65536", "20-10", "abc", "22-", "", True, 2.5, []],
)
def test_parse_port_rejects_out_of_range_and_malformed(value):
    with pytest.raises(PolicyError):
        policy.parse_port(value, "local_port")


def test_validate_action_fills_safe_defaults():
    canonical = policy.validate_action(
        "create_firewall_block_rule", {"remote_address": "203.0.113.7"}
    )

    assert canonical == {
        "remote_address": "203.0.113.7/32",
        "protocol": "tcp",
        "direction": "inbound",
        "profile": "any",
        "local_port": None,
        "remote_port": None,
        "lifetime_minutes": 60,
        "description": None,
    }


def test_validate_action_accepts_full_rule():
    canonical = policy.validate_action(
        "create_firewall_block_rule",
        {
            "remote_address": "2001:db8::1",
            "local_port": "8000-8080",
            "remote_port": 443,
            "protocol": "UDP",
            "profile": "Private",
            "direction": "Outbound",
            "lifetime_minutes": 15,
            "description": "block test host",
        },
    )

    assert canonical["protocol"] == "udp"
    assert canonical["direction"] == "outbound"
    assert canonical["profile"] == "private"
    assert canonical["local_port"] == "8000-8080"
    assert canonical["remote_port"] == "443"
    assert canonical["lifetime_minutes"] == 15


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"remote_address": ""},
        {"remote_address": "203.0.113.7", "protocol": "icmp"},
        {"remote_address": "203.0.113.7", "protocol": "any", "local_port": 22},
        {"remote_address": "203.0.113.7", "direction": "sideways"},
        {"remote_address": "203.0.113.7", "profile": "all"},
        {"remote_address": "203.0.113.7", "lifetime_minutes": 0},
        {"remote_address": "203.0.113.7", "lifetime_minutes": 1441},
        {"remote_address": "203.0.113.7", "lifetime_minutes": "60"},
        {"remote_address": "203.0.113.7", "local_port": 70000},
        {"remote_address": "203.0.113.7", "unexpected": "x"},
        {"remote_address": "203.0.113.7", "description": "<script>"},
        {"remote_address": "203.0.113.7", "description": "a\nb"},
    ],
)
def test_validate_firewall_block_rejects_unsafe_input(params):
    with pytest.raises(PolicyError):
        policy.validate_action("create_firewall_block_rule", params)


def test_validate_action_rejects_non_object_params():
    with pytest.raises(PolicyError):
        policy.validate_action("create_firewall_block_rule", ["203.0.113.7"])


def test_unknown_action_type_is_rejected():
    with pytest.raises(UnknownActionError):
        policy.validate_action("terminate_process", {})
    with pytest.raises(PolicyError):
        policy.validate_action("", {})
    with pytest.raises(PolicyError):
        policy.validate_action(None, {})


def test_rule_name_is_stable_and_cyberguard_owned():
    params = policy.validate_action(
        "create_firewall_block_rule", {"remote_address": "203.0.113.7"}
    )
    first = policy.rule_name_for(params)
    second = policy.rule_name_for(dict(params))

    assert first == second
    assert first.startswith("CyberGuard-Block-In-TCP-")
    assert len(first) <= len("CyberGuard-") + 96


def test_rule_name_differs_by_direction_and_target():
    inbound = policy.validate_action(
        "create_firewall_block_rule",
        {"remote_address": "203.0.113.7", "direction": "inbound"},
    )
    outbound = policy.validate_action(
        "create_firewall_block_rule",
        {"remote_address": "203.0.113.7", "direction": "outbound"},
    )
    other = policy.validate_action(
        "create_firewall_block_rule", {"remote_address": "203.0.113.8"}
    )

    assert policy.rule_name_for(inbound) != policy.rule_name_for(outbound)
    assert policy.rule_name_for(inbound) != policy.rule_name_for(other)


def test_lifetime_and_description_do_not_change_rule_identity():
    base = {"remote_address": "203.0.113.7"}
    first = policy.validate_action(
        "create_firewall_block_rule", {**base, "lifetime_minutes": 5}
    )
    second = policy.validate_action(
        "create_firewall_block_rule",
        {**base, "lifetime_minutes": 90, "description": "hello"},
    )

    assert policy.rule_name_for(first) == policy.rule_name_for(second)


def test_firewall_target_describes_effect_without_raw_input():
    params = policy.validate_action(
        "create_firewall_block_rule",
        {"remote_address": "203.0.113.7", "local_port": 22},
    )
    text = policy.firewall_target(params)

    assert "block inbound TCP" in text
    assert "203.0.113.7" in text
    assert "local port 22" in text


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"rule_name": ""},
        {"rule_name": "SomeOtherRule"},
        {"rule_name": "CyberGuard-"},
        {"rule_name": "CyberGuard-evil rule"},
        {"rule_name": 42},
        {"rule_name": "CyberGuard-ok", "extra": "x"},
    ],
)
def test_remove_requires_a_cyberguard_rule_name(params):
    with pytest.raises(PolicyError):
        policy.validate_action("remove_cyberguard_firewall_rule", params)


def test_remove_accepts_a_cyberguard_rule_name():
    canonical = policy.validate_action(
        "remove_cyberguard_firewall_rule",
        {"rule_name": "CyberGuard-Block-In-TCP-abcdef0123"},
    )

    assert canonical == {"rule_name": "CyberGuard-Block-In-TCP-abcdef0123"}


@pytest.mark.parametrize("value", [0, 501, "10", True, 2.5])
def test_process_limit_is_bounded(value):
    with pytest.raises(PolicyError):
        policy.validate_action("list_processes", {"limit": value})


def test_process_and_connection_defaults():
    assert policy.validate_action("list_processes", {}) == {"limit": 100}
    assert policy.validate_action("list_network_connections", {}) == {
        "limit": 100,
        "protocol": "all",
    }


def test_connection_protocol_is_allowlisted():
    assert policy.validate_action(
        "list_network_connections", {"protocol": "TCP"}
    )["protocol"] == "tcp"
    with pytest.raises(PolicyError):
        policy.validate_action("list_network_connections", {"protocol": "icmp"})


def test_incident_report_defaults_and_validation():
    canonical = policy.validate_action("generate_incident_report", {})
    assert canonical["risk"] == "UNKNOWN"
    assert canonical["title"] == "CyberGuard incident report"

    assert policy.validate_action(
        "generate_incident_report", {"risk": "high"}
    )["risk"] == "HIGH"

    with pytest.raises(PolicyError):
        policy.validate_action("generate_incident_report", {"risk": "severe"})
    with pytest.raises(PolicyError):
        policy.validate_action("generate_incident_report", {"notes": "a" * 2001})


def test_firewall_status_include_raw_must_be_boolean():
    assert policy.validate_action("get_firewall_status", {}) == {
        "include_raw": True
    }
    with pytest.raises(PolicyError):
        policy.validate_action("get_firewall_status", {"include_raw": "yes"})


def test_safe_params_drops_notes_description_and_unknown_keys():
    summary = policy.safe_params(
        "create_firewall_block_rule",
        {
            "remote_address": "203.0.113.7/32",
            "description": "secret detail",
            "notes": "secret note",
            "unknown": "value",
            "lifetime_minutes": 60,
        },
    )

    assert summary == {
        "remote_address": "203.0.113.7/32",
        "lifetime_minutes": 60,
    }


def test_safe_params_truncates_long_values():
    summary = policy.safe_params(
        "generate_incident_report", {"title": "a" * 500}
    )

    assert len(summary["title"]) == 123
    assert summary["title"].endswith("...")


def test_safe_params_handles_non_dict():
    assert policy.safe_params("list_processes", None) == {}
