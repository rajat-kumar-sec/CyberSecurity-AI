from pathlib import Path


KNOWLEDGE_DIR = Path("data/knowledge")


def get_knowledge(threat_type):
    files = {
        "Brute Force": "brute_force.txt",
        "Malware": "malware.txt",
        "Network Scanning": "network_scanning.txt",
        "SQL Injection": "sql_injection.txt",
        "Phishing": "phishing.txt"
    }

    filename = files.get(threat_type)

    if not filename:
        return "No specific knowledge found."

    file_path = KNOWLEDGE_DIR / filename

    if not file_path.exists():
        return "Knowledge file not found."

    return file_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    knowledge = get_knowledge("Brute Force")

    print("=== KNOWLEDGE BASE ===")
    print(knowledge)
