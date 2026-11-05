import pytest

from analyzer import analyze_log
from knowledge import get_knowledge


@pytest.fixture
def sample_logs():
    """One representative log line per supported scenario."""
    return {
        "brute_force": (
            "Failed password for root from 10.0.0.25 port 22 ssh2: "
            "attempts=12, user=root"
        ),
        "malware": "Antivirus alert: trojan detected in C:\\temp\\keylogger.exe",
        "network_scanning": "nmap scan detected from 172.16.0.10, port scan activity",
        "sql_injection": "GET /product?id=1' OR '1'='1 request from 45.33.22.11",
        "phishing": "Email security alert: user received phishing email with malicious link",
        "normal": "System backup completed successfully at 03:00 AM",
    }


@pytest.fixture
def knowledge_texts():
    """Sample snippets that must exist inside each knowledge-base file."""
    return {
        "Brute Force": "brute force",
        "Malware": "malware",
        "Network Scanning": "network scanning",
        "SQL Injection": "sql injection",
        "Phishing": "phishing",
    }


def test_brute_force_rule(sample_logs):
    result = analyze_log(sample_logs["brute_force"])

    assert result["threat_type"] == "Brute Force"
    assert result["risk"] == "HIGH"
    assert result["attempts"] == 12


def test_malware_rule(sample_logs):
    result = analyze_log(sample_logs["malware"])

    assert result["threat_type"] == "Malware"
    assert result["risk"] == "HIGH"


def test_network_scanning_rule(sample_logs):
    result = analyze_log(sample_logs["network_scanning"])

    assert result["threat_type"] == "Network Scanning"
    assert result["risk"] == "MEDIUM"


def test_sql_injection_rule(sample_logs):
    result = analyze_log(sample_logs["sql_injection"])

    assert result["threat_type"] == "SQL Injection"
    assert result["risk"] == "HIGH"


def test_phishing_rule(sample_logs):
    result = analyze_log(sample_logs["phishing"])

    assert result["threat_type"] == "Phishing"
    assert result["risk"] == "HIGH"


def test_benign_log_is_not_flagged(sample_logs):
    result = analyze_log(sample_logs["normal"])

    assert result["risk"] == "LOW"
    assert result["threat_type"] == "Unknown"
    assert result["ml_prediction"] == "Normal"


def test_result_contract(sample_logs):
    """Every analysis must expose the full result contract used by UI/API."""
    result = analyze_log(sample_logs["brute_force"])

    expected_keys = {
        "threat_type", "risk", "username", "source_ip", "attempts",
        "findings", "recommendations", "knowledge",
        "ml_prediction", "ml_confidence",
    }
    assert set(result.keys()) == expected_keys


def test_ml_confidence_is_probabile(sample_logs):
    result = analyze_log(sample_logs["malware"])

    assert 0.0 <= result["ml_confidence"] <= 1.0


def test_extract_ip(sample_logs):
    result = analyze_log(sample_logs["brute_force"])

    assert result["source_ip"] == "10.0.0.25"


def test_extract_ip_missing():
    result = analyze_log("Something happened in the network.")

    assert result["source_ip"] == "Not detected"


def test_extract_username(sample_logs):
    result = analyze_log(sample_logs["brute_force"])

    assert result["username"] == "root"


def test_results_are_independent(sample_logs):
    """analyze_log must not mutate shared state between calls."""
    first = analyze_log(sample_logs["malware"])
    second = analyze_log(sample_logs["malware"])

    assert first["findings"] == second["findings"]
    assert first["ml_prediction"] == second["ml_prediction"]


def test_knowledge_returns_content(knowledge_texts):
    for threat, snippet in knowledge_texts.items():
        text = get_knowledge(threat)

        assert snippet in text.lower(), f"Knowledge for {threat} is missing '{snippet}'"


def test_knowledge_unknown_threat_falls_back():
    assert get_knowledge("Nonexistent Threat") == "No specific knowledge found."


def test_knowledge_missing_file_falls_back():
    assert get_knowledge("Unknown") == "No specific knowledge found."
