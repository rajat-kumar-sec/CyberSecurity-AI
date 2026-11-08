"""Dashboard structure and safe-rendering regression tests.

These tests inspect the rendered HTML and the small set of JavaScript
conventions the UI relies on. They do not execute browser JavaScript.
"""

import pytest

import app as app_module


@pytest.fixture
def client(monkeypatch):
    # Keep the page fast and independent of the vector store.
    monkeypatch.setattr(app_module, "build_context", lambda *a, **k: {
        "query": "",
        "mode": "hybrid",
        "available": False,
        "passages": [],
        "truncated": False,
        "error": "test",
    })
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client


LOG = "Failed password for admin from 10.0.0.5 port 22 ssh2"


def test_dashboard_always_shows_overview_and_read_only_sections(client):
    html = client.get("/").get_data(as_text=True)

    assert 'id="security-overview"' in html
    assert "Security Overview" in html
    assert 'id="network-activity"' in html
    assert "Network Activity" in html
    assert 'id="firewall-status"' in html
    assert "Firewall Status" in html
    assert 'id="action-history"' in html
    assert "Defensive Action History" in html
    assert 'id="defense-panel"' in html


def test_dashboard_analysis_adds_threat_detection_and_chat(client):
    html = client.post("/", data={"log": LOG}).get_data(as_text=True)

    assert 'id="threat-detection"' in html
    assert "Threat Detection" in html
    assert 'id="assistant-chat"' in html
    assert "Assistant Chat" in html
    assert "Machine Learning Analysis" in html
    assert "Recommended Actions" in html


def test_dashboard_states_lifetime_is_not_enforced(client):
    html = client.get("/").get_data(as_text=True)

    assert "recorded, not enforced" in html
    assert "does not remove a Windows Firewall rule automatically" in html


def test_dashboard_states_the_assistant_cannot_execute(client):
    html = client.post("/", data={"log": LOG}).get_data(as_text=True)

    assert "cannot approve or execute" in html


def test_dashboard_does_not_use_innerHTML_for_dynamic_content(client):
    html = client.get("/").get_data(as_text=True)

    assert ".innerHTML" not in html
    assert "= innerHTML" not in html
    assert "textContent" in html


def test_dashboard_never_persists_the_approval_token(client):
    html = client.get("/").get_data(as_text=True)

    assert "localStorage.setItem" not in html
    assert "sessionStorage.setItem" not in html
    assert "The approval token lives only in this closure" in html


def test_dashboard_network_and_firewall_panels_use_read_only_inspection(client):
    html = client.get("/").get_data(as_text=True)

    assert 'action_type: "list_network_connections"' in html
    assert 'action_type: "get_firewall_status"' in html
    assert "No firewall rule or profile was changed" in html


def test_dashboard_shows_backend_form_error(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_LOG_CHARS", 5)

    html = client.post("/", data={"log": "too long"}).get_data(as_text=True)

    assert "at most 5 characters" in html
    assert 'role="alert"' in html
