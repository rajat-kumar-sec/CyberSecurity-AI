import re
from knowledge import get_knowledge


def extract_username(log):
    patterns = [
        r"username:\s*([^\s]+)",
        r"user(?:name)?[=\s]+([^\s]+)",
        r"for\s+(?:invalid user\s+)?([a-zA-Z0-9_.-]+)"
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
    log_lower = log.lower()

    username = extract_username(log)
    source_ip = extract_ip(log)
    attempts = extract_attempts(log)

    findings = []
    recommendations = []

    threat_type = "Unknown"
    risk = "LOW"

    if (
        "failed login" in log_lower
        or "authentication failure" in log_lower
        or "failed password" in log_lower
    ):
        findings.append("Failed authentication attempt detected.")
        threat_type = "Authentication Attack"
        risk = "MEDIUM"
        recommendations.append("Review authentication logs.")

    if (
        "brute force" in log_lower
        or "multiple failed login" in log_lower
        or (attempts is not None and attempts >= 5)
    ):
        findings.append("Possible brute-force attack detected.")
        threat_type = "Brute Force"
        risk = "HIGH"

        recommendations.append("Enable MFA.")
        recommendations.append("Apply login rate limiting.")
        recommendations.append(
            "Check for successful login after the attack."
        )

    if "malware" in log_lower or "ransomware" in log_lower:
        findings.append("Possible malware activity detected.")
        threat_type = "Malware"
        risk = "HIGH"

        recommendations.append("Isolate the affected system.")
        recommendations.append("Run an endpoint security scan.")

    if (
        "port scan" in log_lower
        or "port scanning" in log_lower
        or "nmap" in log_lower
    ):
        findings.append("Possible network scanning activity detected.")
        threat_type = "Network Scanning"

        if risk != "HIGH":
            risk = "MEDIUM"

        recommendations.append("Review firewall and network logs.")
        recommendations.append("Investigate the source IP.")

    if "sql injection" in log_lower or "union select" in log_lower:
        findings.append("Possible SQL injection activity detected.")
        threat_type = "SQL Injection"
        risk = "HIGH"

        recommendations.append("Review web application logs.")
        recommendations.append(
            "Use parameterized database queries."
        )

    if "phishing" in log_lower:
        findings.append("Possible phishing activity detected.")
        threat_type = "Phishing"
        risk = "HIGH"

        recommendations.append("Verify the sender and URL.")
        recommendations.append("Do not open suspicious attachments.")
        recommendations.append("Report the suspicious message.")

    if not findings:
        findings.append("No known suspicious pattern detected.")
        recommendations.append("Continue monitoring the system.")

    knowledge = get_knowledge(threat_type)

    return {
        "risk": risk,
        "threat_type": threat_type,
        "username": username,
        "source_ip": source_ip,
        "attempts": attempts,
        "findings": findings,
        "recommendations": recommendations,
        "knowledge": knowledge
    }


if __name__ == "__main__":
    print("=== CYBERSECURITY AI v0.6 ===")
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

    print()
    print("=== SECURITY ANALYSIS ===")
    print("Threat Type:", result["threat_type"])
    print("Risk Level:", result["risk"])
    print()

    print("Evidence:")
    print("Username:", result["username"])
    print("Source IP:", result["source_ip"])
    print("Attempts:", result["attempts"])
    print()

    print("Findings:")

    for finding in result["findings"]:
        print("-", finding)

    print()
    print("Recommended Actions:")

    for recommendation in result["recommendations"]:
        print("-", recommendation)

    print()
    print("=== KNOWLEDGE BASE CONTEXT ===")
    print(result["knowledge"])
