"""Dashboard structure and safe-rendering regression tests.

These tests inspect the rendered HTML plus the static JavaScript and CSS
assets the Stage 2 (SOC UI 2.0) shell extracted from the legacy template.
They do not execute browser JavaScript.
"""

from pathlib import Path

import pytest

import app as app_module


STATIC_DIR = Path(app_module.__file__).resolve().parent / "static"

DEFENSE_JS = "defense.js"
ASSISTANT_JS = "analysis-assistant.js"
COMPANION_JS = "companion-chat.js"
BATCH_JS = "batch.js"
APP_JS = "app.js"


def static_js(name):
    return (STATIC_DIR / "js" / name).read_text(encoding="utf-8")


def all_static_js():
    return "\n".join(
        static_js(path.name) for path in sorted((STATIC_DIR / "js").glob("*.js"))
    )


def all_static_css():
    return "\n".join(
        (STATIC_DIR / "css" / path.name).read_text(encoding="utf-8")
        for path in sorted((STATIC_DIR / "css").glob("*.css"))
    )


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


def test_sidebar_targets_all_ten_sections(client):
    html = client.get("/").get_data(as_text=True)

    pages = [
        "overview", "log-analysis", "analytics", "monitoring", "defense",
        "audit", "assistant", "companion", "settings", "about",
    ]

    for page in pages:
        assert f'data-page="{page}"' in html, page
        assert f'id="page-{page}"' in html, page


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
    javascript = all_static_js()

    assert ".innerHTML" not in html
    assert "= innerHTML" not in html
    assert ".innerHTML" not in javascript
    assert "= innerHTML" not in javascript
    assert "textContent" in javascript


def test_dashboard_never_persists_the_approval_token(client):
    html = client.get("/").get_data(as_text=True)
    javascript = all_static_js()

    assert "localStorage.setItem" not in html
    assert "sessionStorage.setItem" not in html
    assert "localStorage.setItem" not in javascript
    # The extracted defense module keeps the invariant visible in source.
    assert "The approval token lives only in this closure" \
        in static_js(DEFENSE_JS)


def test_dashboard_network_and_firewall_panels_use_read_only_inspection(client):
    defense = static_js(DEFENSE_JS)
    html = client.get("/").get_data(as_text=True)

    assert 'action_type: "list_network_connections"' in defense
    assert 'action_type: "get_firewall_status"' in defense
    assert "No firewall rule or profile was changed" in defense
    # The panels themselves still ship in the page markup.
    assert 'id="network-refresh"' in html
    assert 'id="firewall-refresh"' in html


def test_batch_module_reports_truncation_honestly(client):
    batch = static_js(BATCH_JS)
    html = client.get("/").get_data(as_text=True)

    assert "CYBERGUARD_BATCH_MAX_LINES" in batch
    assert 'fetch("/api/batch"' in batch
    assert 'id="batch-form"' in html


def test_shell_state_is_read_only_json(client):
    html = client.post("/", data={"log": LOG}).get_data(as_text=True)

    assert 'type="application/json"' in html
    assert 'id="cg-state"' in html


def test_dashboard_shows_backend_form_error(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_LOG_CHARS", 5)

    html = client.post("/", data={"log": "too long"}).get_data(as_text=True)

    assert "at most 5 characters" in html
    assert 'role="alert"' in html


def test_no_telemetry_or_external_origins(client):
    html = client.get("/").get_data(as_text=True)
    css = all_static_css()

    for blob in (html, css, all_static_js()):
        # No CDN/framework/telemetry endpoints may be referenced.
        for marker in ("https://cdn", "https://unpkg", "https://jsdelivr",
                       "google-analytics", "https://fonts.googleapis.com"):
            assert marker not in blob, marker
