def analyze_log(log):
    log_lower = log.lower()

    findings = []
    risk = "LOW"

    if "failed login" in log_lower or "authentication failure" in log_lower:
        findings.append("Failed authentication attempt detected.")
        risk = "MEDIUM"

    if "multiple failed login" in log_lower or "brute force" in log_lower:
        findings.append("Possible brute-force attack detected.")
        risk = "HIGH"

    if "malware" in log_lower or "ransomware" in log_lower:
        findings.append("Possible malware activity detected.")
        risk = "HIGH"

    if "port scan" in log_lower or "nmap" in log_lower:
        findings.append("Possible network scanning activity detected.")
        risk = "MEDIUM"

    if "sql injection" in log_lower or "union select" in log_lower:
        findings.append("Possible SQL injection activity detected.")
        risk = "HIGH"

    if not findings:
        findings.append("No known suspicious pattern detected.")

    return {
        "risk": risk,
        "findings": findings
    }


if __name__ == "__main__":
    print("=== CYBERSECURITY AI ===")
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
    print("Risk Level:", result["risk"])
    print()
    print("Findings:")

    for finding in result["findings"]:
        print("-", finding)
