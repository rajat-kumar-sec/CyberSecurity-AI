import pytest

import analyzer
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_dashboard_get_renders_form(client):
    response = client.get("/")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "SOC Dashboard" in html
    assert "Analyze Security Log" in html


def test_dashboard_post_analyzes_log(client):
    response = client.post("/", data={
        "log": "Failed password for admin from 10.0.0.5 port 22 ssh2: "
               "50 failed attempts for user admin"
    })

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Brute Force" in html
    assert "HIGH" in html


def test_dashboard_post_empty_log_shows_no_result(client):
    response = client.post("/", data={"log": ""})

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Machine Learning Analysis" not in html
    assert "Recommended Actions" not in html


def test_api_analyze_valid_log(client):
    response = client.post("/api/analyze", json={
        "log": "Failed password for admin from 10.0.0.5 port 22 ssh2: "
               "50 failed attempts for user admin"
    })

    assert response.status_code == 200
    body = response.get_json()
    assert body["threat_type"] == "Brute Force"
    assert body["risk"] == "HIGH"
    assert body["ml_prediction"] == "Brute Force"
    assert "recommendations" in body
    assert "knowledge" in body


def test_api_analyze_missing_log_field(client):
    response = client.post("/api/analyze", json={})

    assert response.status_code == 400
    assert response.get_json()["error"] == "Please provide a 'log' field."


def test_api_analyze_whitespace_log(client):
    response = client.post("/api/analyze", json={"log": "   "})

    assert response.status_code == 400
    assert "non-empty" in response.get_json()["error"]


def test_api_analyze_non_string_log(client):
    response = client.post("/api/analyze", json={"log": 12345})

    assert response.status_code == 400
    assert "non-empty" in response.get_json()["error"]


def test_api_analyze_no_json_body(client):
    response = client.post("/api/analyze", data="", content_type="application/json")

    assert response.status_code == 400


def test_json_report_creates_logs_dir(tmp_path, monkeypatch):
    """save_json_report must create the logs directory if it is missing."""
    monkeypatch.setattr(analyzer, "LOGS_DIR", tmp_path / "logs")

    result = {
        "threat_type": "Brute Force",
        "risk": "HIGH",
        "username": "admin",
        "source_ip": "10.0.0.5",
        "attempts": 12,
        "findings": ["Possible brute-force attack detected."],
        "recommendations": ["Enable MFA."],
        "knowledge": "irrelevant",
        "ml_prediction": "Brute Force",
        "ml_confidence": 0.45,
    }

    saved = analyzer.save_json_report(result)
    report_file = tmp_path / "logs" / "latest_report.json"

    assert report_file.exists()
    assert saved["threat_type"] == "Brute Force"
    assert "'username': 'admin'" not in report_file.read_text(encoding="utf-8")
