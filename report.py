def generate_report(result):
    threat = result["threat_type"]
    risk = result["risk"]
    username = result["username"]
    source_ip = result["source_ip"]
    attempts = result["attempts"]

    print()
    print("========================================")
    print("        AI SECURITY REPORT")
    print("========================================")
    print()

    print("Threat:", threat)
    print("Risk Level:", risk)
    print()

    print("Security Summary:")

    if threat == "Brute Force":
        print(
            f"The system detected {attempts} failed authentication "
            f"attempts against the account '{username}' from "
            f"source IP {source_ip}. This pattern is consistent "
            f"with a possible brute-force attack."
        )

    elif threat == "Malware":
        print(
            "The security log contains indicators associated "
            "with possible malware activity."
        )

    elif threat == "Network Scanning":
        print(
            "The log contains indicators of possible network "
            "scanning or reconnaissance activity."
        )

    elif threat == "SQL Injection":
        print(
            "The log contains indicators of possible SQL "
            "injection activity against an application."
        )

    elif threat == "Phishing":
        print(
            "The log contains indicators associated with "
            "possible phishing activity."
        )

    else:
        print(
            "No specific known threat was confidently identified."
        )

    print()
    print("Evidence:")
    print("- Username:", username)
    print("- Source IP:", source_ip)
    print("- Attempts:", attempts)

    print()
    print("Recommended Actions:")

    for recommendation in result["recommendations"]:
        print("-", recommendation)

    print()
    print("Knowledge Source:", threat)
    print("========================================")
