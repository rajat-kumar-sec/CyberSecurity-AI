# CyberSecurity-AI

An AI-powered cybersecurity threat detection and analysis platform.
Paste a security log into the SOC-style dashboard (or the REST API) and get the
threat category, risk level, evidence, findings, defensive recommendations, and
related knowledge-base context — from both a rule engine and a calibrated
machine-learning model.

> Local, lightweight, and offline-friendly: no external services required.

## Features

- **Rule-based threat detection** for five threat categories plus benign traffic:
  - Brute Force, Malware, Network Scanning, SQL Injection, Phishing, Normal/Unknown
- **Evidence extraction** from raw log text: username, source IP, failed-attempt count
- **Calibrated ML classification**: TF-IDF (1–2 grams) + Logistic Regression,
  wrapped in `CalibratedClassifierCV` (sigmoid) for more honest confidence scores
- **Security findings + defensive recommendations** per detected threat
- **Knowledge base**: a curated text reference per threat (indicators, defensive
  measures, investigation steps) attached to every analysis
- **SOC-style dashboard**: dark-UI web interface with risk-level colour coding
- **REST API** (`POST /api/analyze`) for programmatic use
- **JSON + console reports**: structured output saved to `logs/latest_report.json`

## Project Architecture

```
CyberSecurity-AI/
├── app.py                  # Flask app: dashboard (Jinja template) + REST API
├── analyzer.py             # Core engine: rule engine + ML fusion + evidence extraction
├── knowledge.py            # Knowledge-base retriever (exact threat → txt file)
├── report.py               # Console report generator
├── ml_model.py             # Trainer (uncalibrated): TF-IDF + LogReg, train/test split
├── ml_model_v1.py          # Historical trainer iterations (kept intentionally)
├── ml_model_v2.py          #   v2 adds 5-fold StratifiedKFold cross-validation
├── ml_model_v3.py          #   v3 adds sigmoid calibration (produces the saved model)
├── requirements.txt        # Flask, scikit-learn, joblib
├── templates/
│   └── index.html          # Dashboard UI (rendered by Flask)
├── tests/                  # pytest: analyzer, Flask API, knowledge retrieval
├── data/
│   ├── knowledge/          # 5 curated knowledge-base text files
│   └── ml/                 # Labelled training data (CSV)
├── models/
│   └── threat_classifier.joblib   # Trained + calibrated pipeline
└── logs/                   # Generated runtime reports (git-ignored)
```

**Analysis flow:**

```
                ┌──────────────────────────────┐
 log text ──►   │      analyzer.analyze_log    │
                │  1. ML prediction + confidence │
                │  2. Rule engine  → threat/risk │
                │  3. Regex extraction → evidence │
                │  4. Findings + recommendations │
                │  5. Knowledge-base retrieval   │
                └──────────────┬───────────────┘
                               │
        ┌──────────────────────┼────────────────────┐
        ▼                      ▼                    ▼
  Flask dashboard         REST API /api/analyze    CLI report
```

The rule engine and the ML model act as complementary signals: rules give
human-readable findings and stable priority; ML provides category prediction and
a calibrated confidence score.

## Setup

Requires Python 3.10+ (developed on 3.14).

```bash
# 1. Clone
git clone https://github.com/rajat-kumar-sec/CyberSecurity-AI
cd CyberSecurity-AI

# 2. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. (For tests only) install pytest
pip install pytest
```

## Usage

### Dashboard

```bash
python app.py
# open http://127.0.0.1:5000 , paste a log, click "Analyze Security Log"
```

### CLI analyzer

```bash
python analyzer.py
# paste the log, finish with a line containing END
# → console report + logs/latest_report.json
```

### REST API

```bash
curl -X POST http://127.0.0.1:5000/api/analyze ^
     -H "Content-Type: application/json" ^
     -d "{\"log\": \"Failed password for admin from 10.0.0.5 port 22 ssh2: 12 failed attempts for user admin\"}"
```

Response example (abridged):

```json
{
  "threat_type": "Brute Force",
  "risk": "HIGH",
  "ml_prediction": "Brute Force",
  "ml_confidence": 0.45,
  "username": "admin",
  "source_ip": "10.0.0.5",
  "attempts": 12,
  "findings": ["Possible brute-force attack detected."],
  "recommendations": ["Enable MFA.", "Apply login rate limiting.", "..."],
  "knowledge": "Threat: Brute Force Attack ..."
}
```

### Retraining the model

```bash
python ml_model_v3.py    # calibrated pipeline; overwrites models/threat_classifier.joblib
```

Training data: `data/ml/training_data.csv` — single-labelled `log,threat_type` CSV.

## Verified ML Metrics

Reproducible with `python ml_model_v3.py` (scikit-learn 1.9.1, seed 42,
stratified 5-fold cross-validation):

| Dataset                        | Samples | Pipeline                    | Mean 5-fold CV |
|--------------------------------|---------|-----------------------------|----------------|
| `data/ml/training_data.csv`    | 120     | TF-IDF + LogReg **calibrated** (v3, committed model) | **91.67 % ± 5.27** |
| `data/ml/training_data.csv`    | 120     | TF-IDF + LogReg uncalibrated (v2)                    | 92.50 % ± 3.12     |
| `data/ml/training_data_v1.csv` | 40      | TF-IDF + LogReg uncalibrated                         | 70.00 % ± 15.0     |

Classes: `Brute Force, Malware, Network Scanning, Normal, Phishing, SQL Injection`
(20 samples each).

**Honest limitations** — the training logs are built from sentence templates
with varied IPs/usernames, so cross-validation folds can share template
"siblings" and the scores above are optimistic versus fully unseen logs.
Calibration also compresses confidence values (typical 0.25–0.55).
A larger, template-grouped dataset is on the roadmap.

## Running Tests

```bash
pytest -v
```

Covers: the rule engine (all categories), evidence extraction, ML fusion
output shape, JSON report writing, the Flask dashboard and API (including
error handling), and knowledge retrieval (including unknown-threat fallback).

## Roadmap

1. **Retrieval-Augmented Generation (RAG)** over an expanded cybersecurity
   corpus (lightweight sentence embeddings + local vector store).
2. **Conversational assistant** powered by a local open-source LLM that
   explains findings and answers questions.
3. **User-approved conversation memory** — nothing remembered without consent.
4. **Batch log-file analysis**.
5. **Carefully controlled defensive actions** — strict allowlist, explicit
   human confirmation, full audit logging, dry-run mode first.

## Security Disclaimer

This project is for defensive, educational purposes. Detection quality depends
heavily on log format; always verify findings manually before acting.
