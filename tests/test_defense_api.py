"""Flask API tests for the defensive-actions surface.

The app's service is replaced per test with an isolated service that uses a
temporary directory, a fake clock and a fake elevation adapter, so no real
Windows command or firewall change can happen.
"""

import json
from pathlib import Path

import pytest

import app as app_module
from defense import policy
from defense_support import (
    VALID_BLOCK,
    Clock,
    CsrfClient,
    FakeElevation,
    make_service,
)


DEFENSE_JS = (
    Path(app_module.__file__).resolve().parent
    / "static" / "js" / "defense.js"
)


@pytest.fixture
def service(tmp_path, monkeypatch):
    built = make_service(tmp_path, Clock(), elevation=FakeElevation())
    monkeypatch.setattr(app_module, "defense_service", built)
    return built


@pytest.fixture
def client(service):
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as test_client:
        yield CsrfClient(test_client)


@pytest.fixture
def raw_client(service):
    """Unwrapped client for testing the CSRF/Host/Origin guards directly."""
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as test_client:
        yield test_client


def preview(client, params=None, action_type="create_firewall_block_rule"):
    return client.post(
        "/api/defense/actions/preview",
        json={"action_type": action_type, "params": params or VALID_BLOCK},
    )


def approve(client, action_id, action_type="create_firewall_block_rule"):
    return client.post(
        f"/api/defense/actions/{action_id}/approve",
        json={"confirm": action_type},
    )


# ------------------------------------------------------------------ status


def test_status_lists_registered_actions_and_elevation(client):
    response = client.get("/api/defense/status")

    assert response.status_code == 200
    data = response.get_json()
    assert data["available"] is True
    assert data["elevation"]["enabled"] is True
    assert len(data["actions"]) == 7
    assert {item["action_type"] for item in data["actions"]} == {
        "list_processes",
        "list_network_connections",
        "get_firewall_status",
        "generate_incident_report",
        "preview_firewall_block_rule",
        "create_firewall_block_rule",
        "remove_cyberguard_firewall_rule",
    }
    assert data["limitations"]
    assert data["csrf_token"]
    assert data["csrf_header"] == "X-CyberGuard-CSRF"
    assert data["security"]["loopback_only"] is True
    assert data["security"]["csrf_required"] is True
    assert data["security"]["max_body_bytes"] == 64 * 1024


# ----------------------------------------------------------------- inspect


def test_inspect_runs_a_read_only_action(client):
    response = client.post(
        "/api/defense/inspect",
        json={"action_type": "list_processes", "params": {"limit": 5}},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["available"] is True
    assert data["state_changed"] is False
    assert data["count"] == 2


def test_inspect_rejects_a_state_changing_action(client):
    response = client.post(
        "/api/defense/inspect",
        json={"action_type": "create_firewall_block_rule",
              "params": VALID_BLOCK},
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body["error_category"] == "invalid_parameters"
    assert client.get("/api/defense/audit").get_json()["count"] == 0


def test_inspect_rejects_an_unknown_action(client):
    response = client.post(
        "/api/defense/inspect",
        json={"action_type": "terminate_process", "params": {}},
    )

    assert response.status_code == 400
    assert response.get_json()["error_category"] == "unknown_action"


def test_inspect_requires_a_json_object(client):
    response = client.post(
        "/api/defense/inspect", data="not json",
        content_type="application/json",
    )

    assert response.status_code == 400


def test_inspect_rejects_non_object_params(client):
    response = client.post(
        "/api/defense/inspect",
        json={"action_type": "list_processes", "params": ["limit"]},
    )

    assert response.status_code == 400


# ----------------------------------------------------------------- preview


def test_preview_returns_action_and_preview(client):
    response = preview(client)

    assert response.status_code == 201
    data = response.get_json()
    action = data["action"]
    preview_data = data["preview"]
    assert len(action["action_id"]) == 32
    assert action["status"] == "pending"
    assert action["requires_admin"] is True
    assert preview_data["requires_admin"] is True
    assert "203.0.113.7" in preview_data["target"]
    assert preview_data["params"]["direction"] == "inbound"


def test_preview_rejects_invalid_parameters(client):
    response = preview(client, {"remote_address": "999.1.1.1"})

    assert response.status_code == 400
    assert response.get_json()["error_category"] == "invalid_parameters"


def test_preview_rejects_an_unknown_action(client):
    response = preview(client, {}, action_type="format_disk")

    assert response.status_code == 400
    assert response.get_json()["error_category"] == "unknown_action"


def test_preview_requires_a_json_body(client):
    response = client.post("/api/defense/actions/preview", data="")

    assert response.status_code == 400


# ---------------------------------------------------------------- approval


def test_approve_requires_the_exact_confirmation(client):
    action_id = preview(client).get_json()["action"]["action_id"]

    response = client.post(
        f"/api/defense/actions/{action_id}/approve",
        json={"confirm": "yes"},
    )

    assert response.status_code == 409
    assert response.get_json()["error_category"] == "approval_invalid"


def test_approve_returns_a_one_time_token(client):
    action_id = preview(client).get_json()["action"]["action_id"]

    response = approve(client, action_id)

    assert response.status_code == 200
    data = response.get_json()
    assert data["approval"]["single_use"] is True
    assert data["approval_token"]
    assert data["approval_token"] not in str(data["approval"])


def test_approve_unknown_action_is_404(client):
    response = client.post(
        "/api/defense/actions/" + "f" * 32 + "/approve",
        json={"confirm": "create_firewall_block_rule"},
    )

    assert response.status_code == 404
    assert response.get_json()["error_category"] == "action_not_found"


def test_approve_read_only_action_is_rejected(client):
    action_id = client.post(
        "/api/defense/actions/preview",
        json={"action_type": "list_processes", "params": {}},
    ).get_json()["action"]["action_id"]

    response = approve(client, action_id, "list_processes")

    assert response.status_code == 400
    assert response.get_json()["error_category"] == "approval_not_required"


# ----------------------------------------------------------------- execute


def test_execute_without_approval_is_409(client):
    action_id = preview(client).get_json()["action"]["action_id"]

    response = client.post(
        f"/api/defense/actions/{action_id}/execute", json={}
    )

    assert response.status_code == 409
    assert response.get_json()["error_category"] == "approval_required"


def test_execute_requires_a_valid_token(client):
    action_id = preview(client).get_json()["action"]["action_id"]
    approve(client, action_id)

    response = client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={"approval_token": "wrong-token"},
    )

    assert response.status_code == 409
    assert response.get_json()["error_category"] == "approval_invalid"


def test_full_preview_approve_execute_flow(client):
    action_id = preview(client).get_json()["action"]["action_id"]
    token = approve(client, action_id).get_json()["approval_token"]

    response = client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={"approval_token": token},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["changed"] is True
    assert data["rollback_available"] is True


def test_execute_cannot_add_parameters_or_an_approved_boolean(client, service):
    action_id = preview(client).get_json()["action"]["action_id"]
    token = approve(client, action_id).get_json()["approval_token"]

    response = client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={
            "approval_token": token,
            "approved": True,
            "params": {"remote_address": "198.51.100.9"},
        },
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "success"
    active = service.rules.list_active()
    assert active[0]["params"]["remote_address"] == "203.0.113.7/32"


def test_replay_is_rejected(client):
    action_id = preview(client).get_json()["action"]["action_id"]
    token = approve(client, action_id).get_json()["approval_token"]
    client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={"approval_token": token},
    )

    response = client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={"approval_token": token},
    )

    assert response.status_code == 409
    assert response.get_json()["error_category"] == "already_executed"


def test_cancelled_action_cannot_execute(client):
    action_id = preview(client).get_json()["action"]["action_id"]
    token = approve(client, action_id).get_json()["approval_token"]

    cancel = client.post(f"/api/defense/actions/{action_id}/cancel")
    assert cancel.status_code == 200

    response = client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={"approval_token": token},
    )

    assert response.status_code == 409
    assert response.get_json()["error_category"] == "action_cancelled"


def test_execute_of_a_read_only_action_needs_no_approval(client):
    action_id = client.post(
        "/api/defense/actions/preview",
        json={"action_type": "generate_incident_report",
              "params": {"title": "Incident"}},
    ).get_json()["action"]["action_id"]

    response = client.post(
        f"/api/defense/actions/{action_id}/execute", json={}
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "success"


def test_execute_unknown_action_is_404(client):
    response = client.post(
        "/api/defense/actions/" + "0" * 32 + "/execute", json={}
    )

    assert response.status_code == 404
    assert response.get_json()["error_category"] == "action_not_found"


# ---------------------------------------------------------------- rollback


def test_rollback_prepares_a_new_unexecuted_action(client):
    action_id = preview(client).get_json()["action"]["action_id"]
    token = approve(client, action_id).get_json()["approval_token"]
    client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={"approval_token": token},
    )

    response = client.post(
        f"/api/defense/actions/{action_id}/rollback"
    )

    assert response.status_code == 201
    data = response.get_json()
    assert data["action"]["action_type"] == (
        "remove_cyberguard_firewall_rule"
    )
    assert data["action"]["status"] == "pending"
    assert data["preview"]["requires_admin"] is True


def test_rollback_of_read_only_action_is_409(client):
    action_id = client.post(
        "/api/defense/actions/preview",
        json={"action_type": "list_processes", "params": {}},
    ).get_json()["action"]["action_id"]

    response = client.post(
        f"/api/defense/actions/{action_id}/rollback"
    )

    assert response.status_code == 409
    assert response.get_json()["error_category"] == "rollback_not_applicable"


# ------------------------------------------------------------------- audit


def test_audit_is_read_only_and_newest_first(client):
    action_id = preview(client).get_json()["action"]["action_id"]
    token = approve(client, action_id).get_json()["approval_token"]
    client.post(
        f"/api/defense/actions/{action_id}/execute",
        json={"approval_token": token},
    )

    response = client.get("/api/defense/audit?limit=10")

    assert response.status_code == 200
    data = response.get_json()
    assert data["events"][0]["event_type"] == "execution"
    assert data["events"][1]["event_type"] == "approval"
    assert data["events"][2]["event_type"] == "preview"
    assert token not in str(data)


@pytest.mark.parametrize("limit", ["0", "-1", "201", "abc"])
def test_audit_limit_is_validated(client, limit):
    response = client.get(f"/api/defense/audit?limit={limit}")

    assert response.status_code == 400


def test_audit_endpoint_has_no_write_methods(client):
    for method in ("post", "put", "patch", "delete"):
        response = getattr(client, method)("/api/defense/audit")
        assert response.status_code == 405


def test_unknown_action_id_cannot_be_cancelled(client):
    response = client.post(
        "/api/defense/actions/" + "e" * 32 + "/cancel"
    )

    assert response.status_code == 404


def test_dashboard_renders_the_defense_panel(client):
    response = client.get("/")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Defensive Actions" in html
    assert 'id="defense-panel"' in html
    # The Approve button is created by the extracted defense module.
    assert "Approve This Exact Action" in DEFENSE_JS.read_text(encoding="utf-8")


# --------------------------------------------------------- request guards


def test_status_issues_a_session_cookie_and_security_headers(raw_client):
    response = raw_client.get("/api/defense/status")

    assert response.status_code == 200
    assert "cg_defense_session=" in response.headers.get("Set-Cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_write_without_csrf_token_is_rejected(raw_client):
    response = raw_client.post(
        "/api/defense/actions/preview",
        json={"action_type": "create_firewall_block_rule",
              "params": VALID_BLOCK},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 403
    assert response.get_json()["error_category"] == "csrf_required"


def test_write_with_a_wrong_csrf_token_is_rejected(raw_client):
    raw_client.get("/api/defense/status")

    response = raw_client.post(
        "/api/defense/actions/preview",
        json={"action_type": "create_firewall_block_rule",
              "params": VALID_BLOCK},
        headers={"X-CyberGuard-CSRF": "not-the-token"},
    )

    assert response.status_code == 403
    assert response.get_json()["error_category"] == "csrf_required"


def test_non_loopback_client_is_rejected(raw_client):
    response = raw_client.get(
        "/api/defense/status",
        environ_base={"REMOTE_ADDR": "192.0.2.10"},
    )

    assert response.status_code == 403
    assert response.get_json()["error_category"] == "loopback_required"


def test_untrusted_host_header_is_rejected(raw_client):
    response = raw_client.get(
        "/api/defense/status",
        environ_overrides={"HTTP_HOST": "attacker.example:5000"},
    )

    assert response.status_code == 403
    assert response.get_json()["error_category"] == "host_rejected"


def test_cross_origin_write_is_rejected_even_with_a_valid_token(client):
    response = client.post(
        "/api/defense/actions/preview",
        json={"action_type": "create_firewall_block_rule",
              "params": VALID_BLOCK},
        headers={"Origin": "http://attacker.example"},
    )

    assert response.status_code == 403
    assert response.get_json()["error_category"] == "origin_rejected"


def test_same_origin_write_is_allowed(client):
    response = client.post(
        "/api/defense/actions/preview",
        json={"action_type": "create_firewall_block_rule",
              "params": VALID_BLOCK},
        headers={"Origin": "http://localhost"},
    )

    assert response.status_code == 201


def test_cross_site_fetch_metadata_is_rejected(client):
    response = client.post(
        "/api/defense/actions/preview",
        json={"action_type": "create_firewall_block_rule",
              "params": VALID_BLOCK},
        headers={"Sec-Fetch-Site": "cross-site"},
    )

    assert response.status_code == 403
    assert response.get_json()["error_category"] == "origin_rejected"


def test_oversized_defense_body_is_rejected(raw_client):
    payload = b"{" + b" " * (70 * 1024) + b"}"

    response = raw_client.post(
        "/api/defense/actions/preview",
        data=payload,
        content_type="application/json",
    )

    assert response.status_code == 413
    assert response.get_json()["error_category"] == "request_too_large"


def test_nan_and_infinity_are_rejected(client):
    raw = json.dumps({
        "action_type": "create_firewall_block_rule",
        "params": {**VALID_BLOCK, "local_port": float("nan")},
    })

    response = client.post(
        "/api/defense/actions/preview",
        data=raw,
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.get_json()["error_category"] == "invalid_parameters"


def test_dashboard_gets_security_headers(client):
    response = client.get("/")

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Frame-Options"] == "DENY"
