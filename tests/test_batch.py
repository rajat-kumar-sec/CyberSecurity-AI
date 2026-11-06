"""Step 6 tests: batch log-file analysis.

The unit tests inject a fake analyzer so they are fast and deterministic. The
real analyzer is exercised in one parity test to prove that a line analysed in
a batch produces the same verdict as the same line analysed on its own.
"""

import json

import pytest

import batch
from analyzer import analyze_log
from batch import (
    DEFAULT_MAX_LINES,
    HARD_MAX_LINES,
    MAX_LINE_CHARS,
    analyze_bytes,
    analyze_text,
    decode_text,
    max_lines,
    parse_lines,
)

SAMPLES = {
    "Brute Force": "Failed password for root from 10.0.0.7 port 22 ssh2 attempts=20",
    "Malware": "malware trojan detected on workstation ws-14",
    "Network Scanning": "nmap port scan from 10.0.0.9",
    "SQL Injection": "GET /login.php?id=1 UNION SELECT password FROM users",
    "Phishing": "suspicious link in email from attacker@example.com",
    "Unknown": "service started successfully",
}


def fake_analyze(line):
    """Deterministic stand-in for analyzer.analyze_log."""
    text = line.lower()

    if "failed password" in text:
        threat = "Brute Force"
    elif "malware" in text or "trojan" in text:
        threat = "Malware"
    elif "nmap" in text or "port scan" in text:
        threat = "Network Scanning"
    elif "union select" in text:
        threat = "SQL Injection"
    elif "phishing" in text or "suspicious link" in text:
        threat = "Phishing"
    else:
        threat = "Unknown"

    return {
        "threat_type": threat,
        "risk": "HIGH" if threat in ("Brute Force", "Malware", "SQL Injection",
                                     "Phishing") else
                ("MEDIUM" if threat == "Network Scanning" else "LOW"),
        "username": "root" if "root" in text else None,
        "source_ip": "10.0.0.7" if "10.0.0.7" in text else None,
        "attempts": 20 if "attempts=20" in text else None,
        "findings": ["stub"],
        "recommendations": ["stub"],
        "knowledge": {"title": threat},
        "ml_prediction": threat,
        "ml_confidence": 0.5,
    }


# ------------------------------------------------------------------- decoding

def test_decode_text_reads_utf8_with_bom():
    assert decode_text(b"\xef\xbb\xbfhello") == "hello"


def test_decode_text_falls_back_to_latin1():
    # 0xff is not valid UTF-8; Latin-1 keeps the line instead of dropping it.
    assert decode_text(b"caf\xe9") == "café"


def test_decode_text_accepts_str():
    assert decode_text("plain") == "plain"


def test_decode_text_rejects_other_types():
    with pytest.raises(TypeError):
        decode_text(123)


# -------------------------------------------------------------------- parsing

def test_parse_lines_handles_crlf_and_blank_lines():
    parsed = parse_lines("a\r\n\r\n  b  \r\n")

    assert parsed["lines"] == ["a", "b"]
    assert parsed["lines_total"] == 2
    assert parsed["blank_lines"] == 2
    assert parsed["truncated"] is False


def test_parse_lines_is_capped_and_reports_truncation():
    parsed = parse_lines("\n".join(f"line {i}" for i in range(10)), limit=4)

    assert parsed["lines"] == ["line 0", "line 1", "line 2", "line 3"]
    assert parsed["lines_total"] == 10
    assert parsed["truncated"] is True
    assert parsed["limit"] == 4


def test_parse_lines_clips_overlong_lines():
    parsed = parse_lines("x" * (MAX_LINE_CHARS + 50))

    assert len(parsed["lines"][0]) == MAX_LINE_CHARS
    assert parsed["clipped_lines"] == 1


def test_parse_lines_rejects_non_string():
    with pytest.raises(TypeError):
        parse_lines(None)


def test_parse_lines_empty_text():
    parsed = parse_lines("")

    assert parsed["lines"] == []
    assert parsed["lines_total"] == 0
    assert parsed["truncated"] is False


# ---------------------------------------------------------------- line limits

def test_max_lines_defaults_when_env_is_unset(monkeypatch):
    monkeypatch.delenv(batch.MAX_LINES_ENV, raising=False)

    assert max_lines() == DEFAULT_MAX_LINES


def test_max_lines_defaults_when_env_is_invalid(monkeypatch):
    for value in ("", "abc", "0", "-5"):
        monkeypatch.setenv(batch.MAX_LINES_ENV, value)
        assert max_lines() == DEFAULT_MAX_LINES


def test_max_lines_is_capped_at_hard_limit(monkeypatch):
    monkeypatch.setenv(batch.MAX_LINES_ENV, str(HARD_MAX_LINES + 1000))

    assert max_lines() == HARD_MAX_LINES


def test_max_lines_honours_a_valid_env(monkeypatch):
    monkeypatch.setenv(batch.MAX_LINES_ENV, "25")

    assert max_lines() == 25


# ------------------------------------------------------------------- summary

def test_analyze_text_counts_threats_and_risks():
    text = "\n".join(SAMPLES.values())

    report = analyze_text(text, analyze=fake_analyze)

    counts = {row["threat_type"]: row["count"]
              for row in report["threat_types"]}
    assert counts == {
        "Brute Force": 1, "Malware": 1, "Network Scanning": 1,
        "SQL Injection": 1, "Phishing": 1, "Unknown": 1,
    }
    assert report["suspicious"] == 5
    assert report["benign"] == 1
    assert report["lines_analyzed"] == 6
    assert report["lines_total"] == 6
    assert report["available"] is True
    assert report["error"] is None


def test_analyze_text_sorts_threats_by_count():
    text = "\n".join([
        "nmap port scan from 10.0.0.9",
        "nmap port scan from 10.0.0.9",
        "malware trojan detected on workstation ws-14",
    ])

    report = analyze_text(text, analyze=fake_analyze)

    assert report["threat_types"][0] == {"threat_type": "Network Scanning", "count": 2}
    assert report["threat_types"][1] == {"threat_type": "Malware", "count": 1}


def test_analyze_text_sorts_risks_by_severity():
    report = analyze_text("\n".join(SAMPLES.values()), analyze=fake_analyze)

    assert [row["risk"] for row in report["risks"]] == ["HIGH", "MEDIUM", "LOW"]


def test_analyze_text_collapses_duplicate_lines():
    text = "\n".join(["nmap port scan from 10.0.0.9"] * 5)

    report = analyze_text(text, analyze=fake_analyze)

    assert report["unique_lines"] == 1
    assert report["duplicates_collapsed"] == 4
    assert report["suspicious"] == 5
    assert report["threat_types"] == [{"threat_type": "Network Scanning", "count": 5}]


def test_analyze_text_records_line_numbers_in_samples():
    text = "service started\n" + "nmap port scan from 10.0.0.9"

    report = analyze_text(text, analyze=fake_analyze)

    assert len(report["samples"]) == 1
    assert report["samples"][0]["line_number"] == 2
    assert report["samples"][0]["threat_type"] == "Network Scanning"


def test_analyze_text_caps_samples_and_flags_truncation():
    report = analyze_text(
        "\n".join(["nmap port scan from 10.0.0.9"] * 6),
        max_samples=2,
        analyze=fake_analyze,
    )

    assert len(report["samples"]) == 2
    assert report["samples_truncated"] is True


def test_analyze_text_omits_samples_when_nothing_is_suspicious():
    report = analyze_text("service started\nall good", analyze=fake_analyze)

    assert report["samples"] == []
    assert report["samples_truncated"] is False
    assert report["suspicious"] == 0
    assert report["benign"] == 2


def test_analyze_text_reports_a_failing_line_without_dropping_the_rest():
    def flaky(line):
        if "explode" in line:
            raise ValueError("bad line")
        return fake_analyze(line)

    report = analyze_text("explode\nnmap port scan from 10.0.0.9", analyze=flaky)

    assert report["skipped_lines"] == 1
    assert report["error_count"] == 1
    assert "ValueError" in report["errors"][0]["error"]
    assert report["lines_analyzed"] == 1
    assert report["threat_types"] == [{"threat_type": "Network Scanning", "count": 1}]
    assert report["available"] is True


def test_analyze_text_is_truncated_and_reports_total():
    report = analyze_text(
        "\n".join(["nmap port scan from 10.0.0.9"] * 5),
        limit=2,
        analyze=fake_analyze,
    )

    assert report["lines_total"] == 5
    assert report["lines_analyzed"] == 2
    assert report["truncated"] is True


def test_analyze_bytes_decodes_and_analyses():
    report = analyze_bytes(b"nmap port scan from 10.0.0.9", analyze=fake_analyze)

    assert report["suspicious"] == 1
    assert report["filename"] is None


def test_analyze_text_keeps_the_filename():
    report = analyze_text("x", filename="auth.log", analyze=fake_analyze)

    assert report["filename"] == "auth.log"


def test_analyze_text_measures_duration():
    report = analyze_text("x", analyze=fake_analyze)

    assert isinstance(report["duration_ms"], int)
    assert report["duration_ms"] >= 0


# --------------------------------------------------------------------- parity

@pytest.mark.parametrize("log", list(SAMPLES.values()))
def test_batch_verdict_matches_single_log_analysis(log):
    """A line must get the same verdict in a batch and on its own."""
    single = analyze_log(log)
    report = analyze_text(log)

    if report["samples"]:
        sample = report["samples"][0]
        assert sample["threat_type"] == single["threat_type"]
        assert sample["risk"] == single["risk"]
        assert sample["ml_prediction"] == single["ml_prediction"]
        assert sample["ml_confidence"] == single["ml_confidence"]
    else:
        assert single["threat_type"] == "Unknown"
        assert report["threat_types"] == [{"threat_type": "Unknown", "count": 1}]


# ------------------------------------------------------------------------ CLI

def test_cli_prints_a_summary(tmp_path, capsys):
    path = tmp_path / "sample.log"
    path.write_text("nmap port scan from 10.0.0.9\nall good", encoding="utf-8")

    exit_code = batch.main([str(path)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Lines analysed: 2 of 2" in output
    assert "Network Scanning: 1" in output


def test_cli_json_output_is_valid_json(tmp_path, capsys):
    path = tmp_path / "sample.log"
    path.write_text("nmap port scan from 10.0.0.9", encoding="utf-8")

    exit_code = batch.main([str(path), "--json"])

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["suspicious"] == 1
    assert report["threat_types"][0]["threat_type"] == "Network Scanning"


def test_cli_rejects_a_file_over_the_size_limit(tmp_path, capsys):
    path = tmp_path / "big.log"
    path.write_bytes(b"x" * (batch.MAX_UPLOAD_BYTES + 1))

    exit_code = batch.main([str(path)])

    assert exit_code == 2
    assert "limit is" in capsys.readouterr().err


def test_cli_respects_the_line_limit(tmp_path, capsys):
    path = tmp_path / "sample.log"
    path.write_text(
        "\n".join(["nmap port scan from 10.0.0.9"] * 5), encoding="utf-8"
    )

    batch.main([str(path), "--limit", "2"])

    assert "Truncated at 2 lines." in capsys.readouterr().out
