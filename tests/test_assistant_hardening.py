"""Regression tests for assistant grounding/safety and single-log bounds.

These tests never contact a real language model: the Ollama transport is
injected and every "failure" is simulated.
"""

import pytest

import app as app_module
from rag.assistant import (
    DeterministicProvider,
    OllamaProvider,
    answer_looks_like_commands,
    deterministic_answer,
    explain,
)

ANALYSIS = {
    "threat_type": "Brute Force",
    "risk": "HIGH",
    "ml_prediction": "Brute Force",
    "ml_confidence": 0.45,
    "username": "admin",
    "source_ip": "10.0.0.5",
    "attempts": 50,
    "findings": ["Possible brute-force attack detected."],
    "recommendations": ["Enable MFA."],
}


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client


# --------------------------------------------------------- assistant safety

@pytest.mark.parametrize("text", [
    "Run this:\n```\nwhoami\n```",
    "powershell -Command Remove-Item C:\\temp -Recurse",
    "netsh advfirewall set allprofiles state off",
    "cmd.exe /c del important.txt",
    "New-NetFirewallRule -DisplayName bad -Direction Inbound -Action Allow",
])
def test_command_like_answers_are_detected(text):
    assert answer_looks_like_commands(text)


@pytest.mark.parametrize("text", [
    "Review the authentication logs and enable MFA.",
    "The knowledge base describes brute-force indicators.",
    "Ask a human analyst to verify the finding before acting.",
])
def test_prose_answers_are_not_treated_as_commands(text):
    assert not answer_looks_like_commands(text)


def test_ollama_provider_refuses_command_like_output():
    provider = OllamaProvider(
        transport=lambda *args: {
            "message": {"content": "powershell -Command whoami"}
        }
    )

    with pytest.raises(RuntimeError, match="command-like"):
        provider.answer(ANALYSIS, [])


def test_explain_falls_back_when_model_emits_commands():
    provider = OllamaProvider(
        transport=lambda *args: {
            "message": {"content": "netsh advfirewall set allprofiles state off"}
        }
    )

    result = explain(ANALYSIS, [], provider=provider)

    assert result["provider"] == "deterministic"
    assert "command-like" in result["error"]
    assert "advisory only" in result["answer"]
    assert "Deterministic summary" in result["answer"]


def test_explain_publishes_advisory_flags():
    result = explain(ANALYSIS, [], provider=DeterministicProvider())

    assert result["advisory_only"] is True
    assert result["can_approve"] is False
    assert result["can_execute"] is False


def test_deterministic_answer_separates_prediction_from_confirmation():
    answer = deterministic_answer(ANALYSIS, [])

    assert "probabilistic" in answer
    assert "not confirmation" in answer
    assert "rule-based assessment" in answer
    assert "cannot approve, execute or change" in answer


def test_deterministic_answer_still_labels_the_model_boundary():
    answer = deterministic_answer(ANALYSIS, [])

    assert "no language model" in answer


# ----------------------------------------------------- single-log input bounds

def test_api_analyze_rejects_oversized_log(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_LOG_CHARS", 10)

    response = client.post("/api/analyze", json={"log": "x" * 11})

    assert response.status_code == 400
    assert "at most 10 characters" in response.get_json()["error"]


def test_api_assistant_rejects_oversized_log(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_LOG_CHARS", 10)

    response = client.post("/api/assistant", json={"log": "x" * 11})

    assert response.status_code == 400
    assert "at most 10 characters" in response.get_json()["error"]


def test_dashboard_oversized_log_shows_an_error_and_no_analysis(
        client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_LOG_CHARS", 10)

    response = client.post("/", data={"log": "x" * 11})
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "at most 10 characters" in html
    assert "Machine Learning Analysis" not in html


def test_api_analyze_survives_an_analyzer_failure(client, monkeypatch):
    def boom(_log):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(app_module, "analyze_log", boom)

    response = client.post("/api/analyze", json={"log": "a normal log"})

    assert response.status_code == 500
    assert response.get_json()["error"] == "The analysis could not be completed."


def test_api_assistant_survives_an_analyzer_failure(client, monkeypatch):
    def boom(_log):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(app_module, "analyze_log", boom)

    response = client.post("/api/assistant", json={"log": "a normal log"})

    assert response.status_code == 500
    assert response.get_json()["error"] == "The analysis could not be completed."


def test_dashboard_survives_an_analyzer_failure(client, monkeypatch):
    def boom(_log):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(app_module, "analyze_log", boom)

    response = client.post("/", data={"log": "a normal log"})
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "The analysis could not be completed." in html
    assert "Machine Learning Analysis" not in html
