import re
import json
from joblib import load
from knowledge import get_knowledge
from report import generate_report

ML_MODEL_PATH = "models/threat_classifier.joblib"
ml_model = load(ML_MODEL_PATH)


def extract_username(log):
    patterns = [
        r"username\s*[:=]\s*([^\s,]+)",
        r"user\s*[:=]\s*([^\s,]+)",
        r"for\s+(?:invalid\s+user\s+)?([a-zA-Z0-9_.-]+)"
    ]

    for pattern in patterns:
        match = re.search(pattern, log, re.IGNORECASE)
        if match:
            return match.group(1)

    return "Not detected"


def extract_ip(log):
    match = re.search(
        r"\b(?:source ip|src ip|source address|from|src)[=:\s]+"
        r"((?:\d{1,3}\.){3}\d{1,3})",
        log,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return "Not detected"


def extract_attempts(log):
    match = re.search(
        r"(?:attempts?|failed attempts?)[=:\s]+(\d+)",
        log,
        re.IGNORECASE
    )

    if match:
        return int(match.group(1))

    return None


def analyze_log(log):
    ml_prediction = ml_model.predict([log])[0]
    ml_probabilities = ml_model.predict_proba([log])[0]
    ml_confidence = max(ml_probabilities)

    log_lower = log.lower()

    username = extract_username(log)
    source_ip = extract_ip(log)
    attempts = extract_attempts(log)

    findings = []
    recommendations = []

    threat_type = "Unknown"
    risk = "LOW"

    if (
        "brute force" in log_lower
        or "multiple failed login" in log_lower
        or "failed password" in log_lower
        or (attempts is not None and attempts >= 5)
    ):
        findings.append("Possible brute-force attack detected.")
        threat_type = "Brute Force"
        risk = "HIGH"

        recommendations.extend([
            "Enable MFA.",
            "Apply login rate limiting.",
            "Check for successful login after the attack."
        ])

    elif (
        "malware" in log_lower
        or "ransomware" in log_lower
        or "trojan" in log_lower
        or "keylogger" in log_lower
    ):
        findings.append("Possible malware activity detected.")
        threat_type = "Malware"
        risk = "HIGH"

        recommendations.extend([
            "Isolate the affected system.",
            "Run an endpoint security scan.",
            "Investigate suspicious processes and files."
        ])

    elif (
        "nmap" in log_lower
        or "port scan" in log_lower
        or "port scanning" in log_lower
        or "network scanning" in log_lower
    ):
        findings.append("Possible network scanning activity detected.")
        threat_type = "Network Scanning"
        risk = "MEDIUM"

        recommendations.extend([
            "Review firewall and network logs.",
            "Investigate the source IP.",
            "Restrict unnecessary exposed services."
        ])

    elif (
    "sql injection" in log_lower
    or "union select" in log_lower
    or "' or '1'='1" in log_lower
    or "or 1=1" in log_lower
    or "or '1'='1" in log_lower
    or "drop table" in log_lower
    or "insert into" in log_lower
    or "delete from" in log_lower
    or ("update " in log_lower and " set " in log_lower)
):
        findings.append("Possible SQL injection activity detected.")
        threat_type = "SQL Injection"
        risk = "HIGH"

        recommendations.extend([
            "Review web application logs.",
            "Use parameterized database queries.",
            "Validate and sanitize user input."
        ])

    elif (
        "phishing" in log_lower
        or "suspicious link" in log_lower
        or "malicious email" in log_lower
    ):
        findings.append("Possible phishing activity detected.")
        threat_type = "Phishing"
        risk = "HIGH"

        recommendations.extend([
            "Verify the sender and URL.",
            "Do not open suspicious attachments.",
            "Report the suspicious message."
        ])

    elif (
        "failed login" in log_lower
        or "authentication failure" in log_lower
        or "failed password" in log_lower
    ):
        findings.append("Failed authentication attempt detected.")
        threat_type = "Authentication Attack"
        risk = "MEDIUM"

        recommendations.append(
            "Review authentication logs."
        )

    else:
        findings.append("No known suspicious pattern detected.")
        recommendations.append(
            "Continue monitoring the system."
        )

    knowledge = get_knowledge(threat_type)

    return {
        "threat_type": threat_type,
        "risk": risk,
        "username": username,
        "source_ip": source_ip,
        "attempts": attempts,
        "findings": findings,
        "recommendations": recommendations,
        "knowledge": knowledge,
        "ml_prediction": ml_prediction,
        "ml_confidence": round(float(ml_confidence), 4)
    }


def save_json_report(result):
    json_data = {
        "threat_type": result["threat_type"],
        "risk": result["risk"],
        "evidence": {
            "username": result["username"],
            "source_ip": result["source_ip"],
            "attempts": result["attempts"]
        },
        "findings": result["findings"],
        "recommendations": result["recommendations"]
    }

    with open("logs/latest_report.json", "w", encoding="utf-8") as file:
        json.dump(json_data, file, indent=4)

    return json_data


if __name__ == "__main__":
    print("=== CYBERSECURITY AI v0.9 ===")
    print("Structured Security Analysis")
    print()
    print("Paste your security log below.")
    print("Type END on a new line when finished.")
    print()

    lines = []

    while True:
        line = input()

        if line.strip().upper() == "END":
            break

        lines.append(line)

    user_log = "\n".join(lines)

    result = analyze_log(user_log)

    save_json_report(result)

    generate_report(result)

    print()
    print("JSON report saved to:")
    print("logs/latest_report.json")
