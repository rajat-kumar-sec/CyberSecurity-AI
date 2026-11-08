# CyberSecurity-AI

An AI-powered cybersecurity threat detection and analysis platform.
Paste a security log into the SOC-style dashboard (or the REST API) and get the
threat category, risk level, evidence, findings, defensive recommendations, and
related knowledge-base context — from both a rule engine and a calibrated
machine-learning model.

> Local, lightweight, and offline-friendly: no external services required.

> **Scope and safety.** CyberGuard AI is a student/portfolio defensive
> assistant, **not** an enterprise EDR, an antivirus replacement or a fully
> autonomous security platform. The privileged Windows helper is a prototype:
> it is **disabled by default**, has **not** been validated on a real Windows
> host, and is **not approved for production deployment**. Real firewall
> changes require a separate human approval and a verified helper installation.
> See [docs/windows-vm-testing.md](docs/windows-vm-testing.md).

## Features

- **Rule-based threat detection** for five threat categories plus benign traffic:
  - Brute Force, Malware, Network Scanning, SQL Injection, Phishing, Normal/Unknown
- **Evidence extraction** from raw log text: username, source IP, failed-attempt count
- **Calibrated ML classification**: TF-IDF (1–2 grams) + Logistic Regression,
  wrapped in `CalibratedClassifierCV` (sigmoid) for more honest confidence scores
- **Security findings + defensive recommendations** per detected threat
- **Knowledge base**: a curated text reference per threat (indicators, defensive
  measures, investigation steps) attached to every analysis
- **Hybrid knowledge retrieval (RAG)**: BM25 keyword matching fused with local
  sentence-embedding search via Reciprocal Rank Fusion, surfaced in the
  dashboard and through `POST /api/retrieve`. Fully offline after a one-time
  model download. Measured on a 24-query set: hybrid **matches** vector-only
  (MRR 97.9%) — it does not beat it. See [Retrieval (RAG)](#retrieval-rag).
- **Grounded analyst summary**: a deterministic, fully offline explanation of
  each analysis, built from the findings, recommendations and retrieved
  passages
- **Optional local LLM Q&A**: feature-flagged adapter for a locally running
  Ollama server (`POST /api/assistant`). Disabled by default, no cloud calls,
  and any failure falls back to the deterministic answer
- **Chat panel**: ask follow-up questions about the current analysis from the
  dashboard. Vanilla JS, no new dependencies, no persistence, answers rendered
  as text (never HTML)
- **Optional conversation memory**: off by default; when the user ticks a box,
  the browser sends the most recent turns with the next question and the answer
  reports how many were used. Nothing is stored on the server
- **Batch log-file analysis**: upload a `.log`/`.txt` file and get per-line
  verdicts plus a threat/risk summary, from the dashboard or `POST /api/batch`.
  The file is read in memory, never saved
- **Guarded Windows defensive actions (prototype, disabled by default)**: read-only process,
  connection and firewall inspection, plus preview → explicit per-action
  approval → one-shot UAC execution for CyberGuard-owned firewall rules. The
  elevation adapter is disabled by default, approvals are single-use and
  expiring, every outcome is audited, and there is no process termination or
  automatic blocking. See
  [Defensive actions](#defensive-actions-windows-per-action-approval)
- **SOC-style dashboard**: dark-UI web interface with risk-level colour coding
  and dedicated Security Overview, Threat Detection, Network Activity, Firewall
  Status, Defensive Action History and Assistant Chat sections. Network and
  firewall panels are read-only and run only on demand; unavailable data is
  labelled instead of invented
- **REST API** (`POST /api/analyze`, `POST /api/retrieve`, `POST /api/assistant`,
  `POST /api/batch`, `/api/defense/*`) for programmatic use
- **JSON + console reports**: structured output saved to `logs/latest_report.json`

## Project Architecture

```
CyberSecurity-AI/
├── app.py                  # Flask app: dashboard (Jinja template) + REST API
├── analyzer.py             # Core engine: rule engine + ML fusion + evidence extraction
├── batch.py                # Line-by-line log-file analysis (API + CLI)
├── knowledge.py            # Knowledge-base retriever (exact threat → txt file)
├── report.py               # Console report generator
├── ml_model.py             # Trainer (uncalibrated): TF-IDF + LogReg, train/test split
├── ml_model_v1.py          # Historical trainer iterations (kept intentionally)
├── ml_model_v2.py          #   v2 adds 5-fold StratifiedKFold cross-validation
├── ml_model_v3.py          #   v3 adds sigmoid calibration (produces the saved model)
├── rag/                    # Retrieval layer (optional dependency set)
│   ├── chunker.py          # Section-aware knowledge chunking
│   ├── embedder.py         # FastEmbed MiniLM embeddings (384-d, ONNX)
│   ├── store.py            # Persistent Chroma vector store
│   ├── retriever.py        # BM25 / vector / RRF hybrid retrieval
│   ├── evaluate.py         # Recall@3, Recall@5, MRR evaluation
│   ├── context.py          # App-facing retrieval context (Step 4)
│   └── assistant.py        # Grounded context supply + optional local LLM (Step 5)
├── defense/                # Guarded defensive actions (standard library only)
│   ├── models.py           # Typed actions, approvals, results, audit events
│   ├── registry.py         # Fixed allowlist of seven actions (no plugins)
│   ├── policy.py           # Fail-closed parameter validation and rule naming
│   ├── approvals.py        # In-memory action store + single-use approval store
│   ├── executor.py         # Preview → approve → execute → verify → audit
│   ├── audit.py            # Append-only JSONL history (git-ignored)
│   ├── rollback.py         # Inverse-action preparation with ownership checks
│   ├── service.py          # Facade used by app.py
│   └── windows/            # Windows-only layer (lazily imported)
│       ├── security.py     # ACL, reparse-point, atomic-write helpers
│       ├── inspection.py   # Fixed-argv tasklist / netstat / netsh reads
│       ├── firewall.py     # Fixed-argv netsh rules + ownership registry
│       └── elevated.py     # One-shot HMAC-signed UAC helper
├── docs/
│   ├── architecture.md     # Mermaid architecture + trust boundaries
│   ├── windows-vm-testing.md  # Privileged validation procedure (not executed)
│   └── performance.md      # Measured startup/retrieval/batch/memory results
├── ingest_knowledge.py     # Idempotent knowledge-base ingestion CLI
├── requirements.txt        # Flask, scikit-learn, joblib (core only)
├── rag/requirements.txt    # Isolated RAG dependencies (never merged into core)
├── templates/
│   └── index.html          # Dashboard UI (rendered by Flask)
├── tests/                  # pytest: analyzer, API, RAG, retrieval, defense
├── data/
│   ├── knowledge/          # 5 curated knowledge-base text files
│   ├── eval/               # Retrieval evaluation dataset (24 queries)
│   ├── vectorstore/        # Generated Chroma store (git-ignored)
│   ├── defense/            # Audit, rule ownership, secret (git-ignored)
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

At the application layer, each analyzed log also receives a **retrieved
context** block — hybrid BM25 + embedding search over the same knowledge base.
This is purely additive: `analyzer.py` is untouched, the exact-name reference is
still attached, and if the optional RAG packages or the vector store are
missing, retrieval is reported as unavailable instead of failing the request.

For the full component diagram, request sequences and trust boundaries, see
[docs/architecture.md](docs/architecture.md).

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

### Optional: knowledge retrieval (RAG)

The dashboard and API work without these packages; retrieval simply reports
itself as unavailable. To enable hybrid retrieval:

```bash
pip install -r rag\requirements.txt      # Windows
# pip install -r rag/requirements.txt    # Linux/macOS

python ingest_knowledge.py               # one-off: ~87 MB model download, builds data/vectorstore/
```

`rag/requirements.txt` is intentionally separate from `requirements.txt` so the
core analyzer never depends on the retrieval stack.

## Usage

### Dashboard

```bash
python app.py
# open http://127.0.0.1:5000 , paste a log, click "Analyze Security Log"
```

The dashboard is organised into six sections:

| Section | Behaviour |
| --- | --- |
| Security Overview | Analysis status, detected threat/risk, last analysis metadata and local readiness. Unavailable data is labelled. |
| Threat Detection | Rule findings, ML prediction/confidence (with an explicit "not confirmation" caveat), evidence, recommendations and retrieved knowledge. |
| Network Activity | On-demand, read-only `netstat -ano` snapshot (PID only; no process-name resolution). |
| Firewall Status | On-demand, read-only Domain/Private/Public profile state; raw text when parsing fails. |
| Defensive Action History | Read-only audit history including approval, elevation and unknown/unverified outcomes. |
| Assistant Chat | Grounded Q&A; advisory only, no approval or execution capability. |

The server binds to `127.0.0.1` by default and refuses to bind the defensive API
to a public interface by accident.

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

### Semantic knowledge retrieval

```bash
curl -X POST http://127.0.0.1:5000/api/retrieve ^
     -H "Content-Type: application/json" ^
     -d "{\"query\": \"someone probing my ports\", \"top_k\": 3, \"mode\": \"hybrid\"}"
```

`mode` is one of `hybrid` (default), `bm25`, `vector`; `top_k` must be 1–20.
Response (abridged):

```json
{
  "query": "someone probing my ports",
  "mode": "hybrid",
  "available": true,
  "truncated": false,
  "error": null,
  "passages": [
    {
      "id": "knowledge-...",
      "title": "Network Scanning",
      "source_file": "network_scanning.txt",
      "category": "Network Scanning",
      "section": "Common Indicators",
      "snippet": "Network Scanning - Common Indicators: ...",
      "score": 0.0325,
      "retrieval_sources": ["bm25", "vector"]
    }
  ]
}
```

The dashboard renders the same passages in a **Related Knowledge** panel after
an analysis, and `POST /api/analyze` includes them under `retrieved_context`.

### Grounded assistant

The dashboard exposes the same endpoint through an **Ask About This Analysis**
chat panel: analyse a log, type a question, and the answer is appended to the
transcript with its provider and citation list. The panel is plain JavaScript,
loads no third-party script, and keeps the transcript in the DOM only.

```bash
curl -X POST http://127.0.0.1:5000/api/assistant ^
     -H "Content-Type: application/json" ^
     -d "{\"log\": \"Failed password for admin from 10.0.0.5 port 22 ssh2: 50 failed attempts\", \"question\": \"What should I check first?\"}"
```

Response (abridged):

```json
{
  "analysis": { "threat_type": "Brute Force", "risk": "HIGH" },
  "retrieved_context": { "available": true, "passages": [] },
  "assistant": {
    "answer": "Brute Force detected with HIGH risk. ... [1] ...",
    "provider": "deterministic",
    "model": null,
    "error": null,
    "available": true,
    "question": "What should I check first?",
    "citations": [ { "index": 1, "category": "Brute Force", "section": "Investigation Steps" } ],
    "grounded_on": 4
  }
}
```

By default no model is involved. To route the same request to a local LLM:

```bat
set CYBERGUARD_LLM_PROVIDER=ollama
set CYBERGUARD_LLM_MODEL=qwen2.5:1.5b
ollama pull qwen2.5:1.5b
```

If the server is not running, the model is missing, or the request times out,
the answer falls back to the deterministic summary and `error` records why.

To continue a conversation, send the earlier turns yourself (opt-in memory):

```bash
curl -X POST http://127.0.0.1:5000/api/assistant ^
     -H "Content-Type: application/json" ^
     -d "{\"log\": \"...\", \"question\": \"And then?\", \"history\": [{\"role\": \"user\", \"content\": \"What first?\"}, {\"role\": \"assistant\", \"content\": \"Review auth logs [1].\"}]}"
```

The response then includes `"history_used": 2`, and the deterministic answer
states that it is continuing from 2 earlier messages. Omit `history` and the
request is stateless, exactly as before.

### Batch log-file analysis

Upload a file (multipart field `file`) or send its text as JSON:

```bash
curl -X POST http://127.0.0.1:5000/api/batch -F "file=@C:\logs\auth.log"
```

```bash
curl -X POST http://127.0.0.1:5000/api/batch ^
     -H "Content-Type: application/json" ^
     -d "{\"content\": \"nmap port scan from 10.0.0.9\\nservice started\", \"filename\": \"scan.log\"}"
```

Response (abridged):

```json
{
  "available": true,
  "filename": "auth.log",
  "lines_total": 200,
  "lines_analyzed": 200,
  "truncated": false,
  "limit": 200,
  "suspicious": 125,
  "benign": 75,
  "threat_types": [
    { "threat_type": "Unknown", "count": 75 },
    { "threat_type": "Brute Force", "count": 25 }
  ],
  "risks": [ { "risk": "HIGH", "count": 100 }, { "risk": "MEDIUM", "count": 25 }, { "risk": "LOW", "count": 75 } ],
  "samples": [
    { "line_number": 1, "threat_type": "Brute Force", "risk": "HIGH", "source_ip": "10.0.0.7", "username": "root", "attempts": 20, "snippet": "..." }
  ],
  "errors": [],
  "error_count": 0,
  "duration_ms": 4280
}
```

Limits and behaviour:

| Limit | Value | Why |
|---|---|---|
| File size | 1 MiB | read fully into memory |
| Lines analysed | 200 (`CYBERGUARD_BATCH_MAX_LINES`, hard cap 2000) | the analyzer runs one model prediction per line |
| Sample rows | 50 suspicious lines per response | keeps the payload small |

Each line is passed to the **same** `analyzer.analyze_log` used by the
single-log form, so a line's verdict does not depend on how it was submitted.
Identical lines are analysed once and mapped back, and lines that fail are
counted in `error_count` with an example in `errors` instead of failing the
whole file. A file larger than the line cap reports `truncated: true` together
with `lines_total`, so nothing is silently ignored.

The same engine runs offline from the CLI, which has no request timeout:

```bash
python batch.py logs\auth.log            # human-readable summary
python batch.py logs\auth.log --json     # full report
python batch.py logs\auth.log --limit 1000
```

Measured on the reference laptop: **200 lines in 3.6–4.3 s** (roughly 18–21 ms
per line, including one scikit-learn prediction per line).

### Defensive actions (Windows, per-action approval)

This is a deliberately small, explicit and conservative prototype of the
defensive-actions subsystem. It is **not production-approved**, and the
privileged helper has not been validated on a real Windows host. The threat
analyzer may *recommend* an action; it can never approve or execute one. Every
state-changing action requires a separate preview, a separate human approval and
a separate execute request. See
[docs/windows-vm-testing.md](docs/windows-vm-testing.md) for the procedure that
must pass before elevation is considered safe.

#### Supported actions (fixed allowlist)

| Action | Changes state | Admin | Notes |
|---|---|---|---|
| `list_processes` | no | no | fixed `tasklist /FO CSV /NH` (resolved via `%SystemRoot%\System32`) |
| `list_network_connections` | no | no | fixed `netstat -ano` (resolved via `%SystemRoot%\System32`) |
| `get_firewall_status` | no | no | fixed `netsh advfirewall show allprofiles state` (resolved via `%SystemRoot%\System32`) |
| `generate_incident_report` | no | no | in-memory only; writes no file |
| `preview_firewall_block_rule` | no | no | shows the exact rule that would be created |
| `create_firewall_block_rule` | yes | **yes** | one CyberGuard-owned block rule |
| `remove_cyberguard_firewall_rule` | yes | **yes** | only recorded CyberGuard rules |

Unknown action types are rejected. No request field accepts a command string,
executable path, shell fragment or PowerShell text. Process termination and
Defender/antivirus/firewall disabling are **not implemented**.

#### Workflow and API

The defensive API is a **loopback-only approval surface**, not a public web API.
Every `/api/defense/*` request must come from `127.0.0.1`/`::1`, carry an
allowed loopback `Host`, and state-changing requests need a session-bound CSRF
token. The dashboard handles this automatically. For `curl`, bootstrap a session
first and send the returned token:

```powershell
# 0. Bootstrap CSRF: save the cookie and read csrf_token/csrf_header
curl.exe -c cookies.txt http://127.0.0.1:5000/api/defense/status
# csrf_token is in the JSON response; csrf_header is X-CyberGuard-CSRF
```

```bash
# 1. Read-only inspection (no approval needed)
curl -X POST http://127.0.0.1:5000/api/defense/inspect ^
     -H "Content-Type: application/json" ^
     -H "X-CyberGuard-CSRF: <csrf_token>" ^
     -d "{\"action_type\": \"list_processes\", \"params\": {\"limit\": 25}}"

# 2. Prepare an exact, non-executed action -> returns action_id + preview
curl -X POST http://127.0.0.1:5000/api/defense/actions/preview ^
     -H "Content-Type: application/json" ^
     -d "{\"action_type\": \"create_firewall_block_rule\", \"params\": {\"remote_address\": \"203.0.113.7\", \"local_port\": 22, \"protocol\": \"tcp\", \"profile\": \"any\", \"lifetime_minutes\": 30}}"

# 3. Explicit approval -> returns a single-use token exactly once
curl -X POST http://127.0.0.1:5000/api/defense/actions/<action_id>/approve ^
     -H "Content-Type: application/json" ^
     -d "{\"confirm\": \"create_firewall_block_rule\"}"

# 4. Execute the approved action exactly once
curl -X POST http://127.0.0.1:5000/api/defense/actions/<action_id>/execute ^
     -H "Content-Type: application/json" ^
     -d "{\"approval_token\": \"<token>\"}"

# Optional: cancel, prepare rollback, read audit
curl -X POST http://127.0.0.1:5000/api/defense/actions/<action_id>/cancel
curl -X POST http://127.0.0.1:5000/api/defense/actions/<action_id>/rollback
curl "http://127.0.0.1:5000/api/defense/audit?limit=25"
```

`GET /api/defense/status` reports capabilities, platform, elevation state,
active rule count and known limitations. There is no endpoint that executes an
action merely because a client sends an action type and parameters, and there
is no write/delete endpoint for the audit log.

All state-changing requests return structured errors with a stable
`error_category`, for example `approval_required`, `approval_invalid`,
`approval_expired`, `approval_used`, `already_executed`, `action_cancelled`,
`action_expired`, `elevation_disabled`, `helper_untrusted`, `uac_cancelled`,
`uac_denied`, `execution_unknown`, `unsupported_os`, `csrf_required`,
`host_rejected`, `origin_rejected`, `request_too_large` and `rate_limited`.

The API refuses bodies larger than 64 KiB, non-finite JSON numbers, non-loopback
clients, non-loopback `Host` values and cross-origin/cross-site browser
requests. These controls reduce cross-site forgery and DNS-rebinding risk; they
are **not** OS-level authentication and are not proof that a human is physically
present.

#### Approval model

* An approval is bound to the exact action id, action type, canonical parameter
  hash and expiry (5 minutes).
* The token is unpredictable, stored only as a SHA-256 hash, and consumed
  atomically before anything runs. Replay, a second execution and a stale token
  are rejected.
* Changing any parameter after approval invalidates it.
* Cancelling an action revokes its approval permanently.
* Prepared actions expire after 15 minutes. Both stores are process-local, so a
  server restart invalidates every pending action and approval (fail closed).
* The approval token is returned once to the caller and never written to the
  audit log or rendered in the dashboard.

#### One-shot UAC hand-off (disabled by default)

State-changing actions never run in the Flask process. The executor writes one
signed request file and launches one short-lived helper with the Windows `runas`
verb:

```text
<protected-python.exe> -I -m defense.windows.elevated --request <32-hex-nonce>.json
```

The helper is launched in Python isolated mode (`-I`: no user site, no
`PYTHONPATH`, no script-directory injection) with an absolute interpreter and an
administrator-protected working directory. It independently verifies:

* that it is elevated;
* that the request path is inside the request directory, is a regular
  single-link file and is not a symlink/junction/reparse point;
* that the HMAC-SHA256 signature, nonce, issue time and expiry are valid;
* that the action type and parameters revalidate to the same canonical values;
* that a persistent per-nonce consumption marker has not already been used;
* for removals, that CyberGuard's own validated record still owns the exact rule
  identity.

It then runs only a fixed `netsh` argv list with `shell=False`, verifies the
resulting rule's important properties, and writes a signed result. A timeout is
reported as `execution_unknown`; it is never converted into success or a
definitive failure and is never retried automatically.

**Elevation stays disabled unless a genuinely administrator-protected helper
installation can be verified.** A repository checkout, an ordinary virtual
environment and a bare absolute path are not trusted. Set all of:

```powershell
# Only after installing the code and interpreter in an administrator-only root
$env:CYBERGUARD_DEFENSE_HELPER_ROOT = "C:\ProgramData\CyberGuard\helper"
$env:CYBERGUARD_DEFENSE_DIR      = "C:\ProgramData\CyberGuard\data"
$env:CYBERGUARD_DEFENSE_ELEVATION = "1"
python app.py
```

The helper root must be absolute, contain both `sys.executable` and
`defense/windows/elevated.py`, and the root, interpreter and module must all
pass an **admin-only** DACL check (only `SYSTEM` and `Administrators`; the
interactive user is not granted access). The HMAC key must already exist with
exactly 32 bytes and a verified restricted ACL; an existing empty, short,
oversized or ACL-unverified key is rejected and never regenerated.

Without `CYBERGUARD_DEFENSE_ELEVATION=1`, preview/approval/audit still work and
execution honestly returns `elevation_disabled`. With it set but an untrusted
installation, execution returns `helper_untrusted` instead of running. The Flask
server is never elevated, and no permanent Windows service or background admin
process is created.

#### Storage, audit and rollback

`data/defense/` is git-ignored and can be relocated with
`CYBERGUARD_DEFENSE_DIR`. It contains:

| File | Purpose |
|---|---|
| `audit.jsonl` | append-only, sanitized audit history (rotated at 2 MiB) |
| `rules.json` | CyberGuard's own validated record of the rules it created |
| `secret.key` | per-install 32-byte HMAC key for the UAC hand-off |
| `requests/` | transient signed one-shot requests |
| `consumed/` | persistent per-nonce replay markers |

On Windows, the data directory and secret use a restricted DACL (current user,
`SYSTEM`, `Administrators`). This protects against other standard users but
**not** against malware running as the same interactive user.

The audit log records the timestamp, action id/type, target, a whitelisted
parameter summary, approval outcome, execution outcome, error category and
rollback status. Tokens, passwords and free-form notes/descriptions are dropped
before writing. The dashboard only reads the newest 25 events and marks the
listing as truncated when older events exist. The audit file is append-only
through the application, but it is **not tamper-proof**: a local administrator
or same-user process can edit or delete it outside CyberGuard.

Rollback is **preparation only**: it creates the inverse action (remove a rule
it created, or re-create a rule it removed with the recorded original
parameters) that must go through its own preview/approve/execute cycle.
Rollback is refused when CyberGuard cannot positively identify the rule, the
action that owns it and the exact canonical parameters. A corrupt ownership
registry is fail-closed: it is reported and never silently replaced.

#### Limitations

* Windows Firewall has no native rule TTL. `lifetime_minutes` is validated and
  recorded, and the audit/status expose it, but an expired rule remains until
  it is removed (there is no background janitor). The dashboard says this
  explicitly.
* Removal is limited to rules with the `CyberGuard-` prefix that also exist in
  `rules.json`; unrelated firewall rules are never touched.
* Read-only inspection and UAC execution are Windows-only. On other platforms
  they return `unsupported_os` instead of guessing.
* The audit log is append-only through the application, but it is a local
  user-owned file: the owning user or a local administrator can alter it.
* There is no automatic remediation, no automatic IP blocking and no process
  termination.
* Same-user processes can still tamper with CyberGuard's user-owned data
  directory. The HMAC hand-off protects the request/result protocol, not the
  whole host.
* The CSRF/loopback/Host/Origin checks are not OS-level authentication and do
  not prove physical user presence; the explicit approval step remains a
  procedural control.
* Localized `netsh` output that cannot be parsed is reported as
  `unsupported_firewall_output` rather than guessed.
* Real Windows validation of ACLs, reparse/junction/hardlink behaviour,
  PATH/module hijacking, UAC and localized `netsh` output still requires a
  dedicated Windows VM test pass; the automated suite mocks all of it.

### Retraining the model

```bash
python ml_model_v3.py    # calibrated pipeline; overwrites models/threat_classifier.joblib
```

Training data: `data/ml/training_data.csv` — single-labelled `log,threat_type` CSV.

## Retrieval (RAG)

```
query ──► BM25 keyword search (rank-bm25, 26 chunks)     ──┐
      └─► vector search (FastEmbed MiniLM → Chroma)      ──┤
                                                          ▼
                        RRF: score(d) = Σ wᵣ / (k + rankᵣ(d))
                                                          ▼
                    structured passages (deduped by chunk id)
```

- **Chunking:** one chunk per section (`Description`, `Common Indicators`, …),
  deterministic content-derived IDs, full rebuild on every ingest.
- **Embeddings:** `sentence-transformers/all-MiniLM-L6-v2` via FastEmbed
  (ONNX, 384-d, Apache-2.0). Same model family and dimension as the torch
  pipeline, but vectors are not guaranteed bit-identical to it.
- **Fusion:** Reciprocal Rank Fusion (`k=60`, equal weights by default),
  deduped by chunk ID, configurable weights and candidate depth.
- **Degradation:** empty query → no passages; missing vector store → BM25
  results only; missing RAG packages → `available: false`, request still succeeds.

### Measured retrieval quality

24 realistic queries (`data/eval/retrieval_eval.json`), top-k = 5:

| Mode | Recall@3 | Recall@5 | MRR |
|---|---|---|---|
| BM25 | 100.0 % | 100.0 % | 86.8 % |
| Vector | 100.0 % | 100.0 % | 97.9 % |
| **Hybrid (RRF)** | 100.0 % | 100.0 % | **97.9 %** |

Honest reading: on this small five-category knowledge base, **hybrid ties
vector-only** and beats BM25; it is *not* demonstrated to improve accuracy.
Its practical value is robustness — BM25 keeps results flowing without a
vector store, and fusion hedges ranker errors. Recall saturates because any
expected category in the top 5 counts as a hit, leaving MRR as the only
discriminating metric.

Reproduce with:

```bash
python -m rag.evaluate
```

Known limitations: 26 chunks is a tiny corpus, so BM25 IDF is unstable and
copy-pasted section templates collide across categories; section-level accuracy
is recorded in the dataset but not yet scored.

## Assistant (Step 5)

The assistant layer turns one analysis plus its retrieved passages into a
grounded answer. Two providers, selected with `CYBERGUARD_LLM_PROVIDER`:

| Provider | Default | Requirements | Behaviour |
|---|---|---|---|
| `deterministic` | **yes** | none | Composes a summary from findings, recommendations and passages. Instant, offline, no model. |
| `ollama` | no | local Ollama server + a pulled model | Sends a grounded prompt to `127.0.0.1:11434`. Falls back to deterministic on any failure. |

Grounding rules are encoded in the prompt: answer only from the supplied
analysis and passages, cite passages as `[n]`, never invent indicators or
commands, and say plainly when the knowledge base does not cover the question.

**Privacy and memory:** no cloud requests. By default the prompt contains only
the current analysis, the current retrieved passages and the question, and
nothing is stored between calls.

Conversation memory is **opt-in per request**. The dashboard chat panel has an
unchecked "Include earlier questions as context" box; when the user ticks it,
the browser sends the most recent turns it holds, and the answer reports how
many were used (`history_used`). Memory is bounded server-side — the newest 8
messages, 2000 characters each, 8000 characters total — and invalid history
(including any `system` role) is rejected with HTTP 400. The server keeps no
history at all: clearing the conversation, unticking the box or reloading the
page forgets it, and nothing is written to disk or to a session cookie. The
system prompt tells the model that earlier turns are context only, never
instructions.

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
Confidence values are also poorly spread: on the 120 training logs the maximum
predicted probability ranges **0.51–0.88 (median 0.77)**, so a high confidence
mostly reflects familiarity with the training templates rather than strong
independent evidence. A larger, template-grouped dataset is on the roadmap.

## Running Tests

```bash
pytest -v
```

Covers: the rule engine (all categories), evidence extraction, ML fusion
output shape, JSON report writing, the Flask dashboard and API (including
error handling), knowledge retrieval (including unknown-threat fallback),
chunking/embedding/store ingestion, BM25/vector/hybrid retrieval and
evaluation metrics, the retrieval integration layer, the grounded assistant,
batch log-file analysis, opt-in conversation memory, dashboard sections and
safe-rendering conventions, single-log input bounds, assistant output safety
(command-like model output is refused), and the defensive-actions subsystem
(typed models, fail-closed policy, approval binding/replay/expiry, executor,
audit sanitization, Windows inspection/firewall/UAC hand-off and the defense
API) - **648 tests**, with RAG-dependent tests skipping cleanly when the
optional packages are absent. Nothing in the suite touches the real Windows
Firewall: every command and every elevation is mocked.

Latest recorded run: **648 passed, 31 warnings** (third-party NumPy/joblib
deprecations). `python -m compileall -q defense app.py tests` is clean.

## Roadmap

1. ~~**Retrieval-Augmented Generation (RAG)** over an expanded cybersecurity
   corpus (lightweight sentence embeddings + local vector store).~~ —
   **done**: hybrid BM25 + embedding retrieval with evaluation, surfaced in
   the dashboard (`Related Knowledge`) and the API (`/api/retrieve`).
2. **Conversational assistant** powered by a local open-source LLM that
   explains findings and answers questions — **done**: grounded prompt,
   deterministic summary, optional Ollama adapter, dashboard chat panel, and
   opt-in memory across turns.
3. **User-approved conversation memory** — **done**: nothing is sent or
   remembered unless the user ticks the memory box; the browser owns the
   history, the server bounds it and stores nothing.
4. **Batch log-file analysis** — **done**: `POST /api/batch` and
   `python batch.py <file>` analyse a file line by line with the same engine,
   summarise threats/risks, and cap work per request (200 lines by default,
   hard cap 2000) so a large file cannot stall the app.
5. **Carefully controlled defensive actions** — **prototype, not
   production-approved**: fixed seven-action allowlist, preview → explicit
   per-action approval → one-shot HMAC-signed UAC helper for CyberGuard-owned
   firewall rules, fail-closed parameter validation, append-only sanitized audit
   and ownership-checked rollback preparation. Process termination and
   automatic blocking remain intentionally out of scope; the elevation adapter
   is disabled by default, the Flask server is never elevated, and real Windows
   validation is still required (see
   [docs/windows-vm-testing.md](docs/windows-vm-testing.md)).
6. **Broader evaluation and deployment hardening** — not started: a larger,
   template-grouped ML dataset, real-Windows ACL/UAC validation, and
   multi-process concurrency testing.

## Security Disclaimer

This project is for defensive, educational and portfolio purposes.

- It is **not** an enterprise EDR, an antivirus replacement, a SIEM, or a fully
  autonomous security platform.
- Detection quality depends heavily on log format and on the small training
  dataset. ML confidence is not proof of an attack.
- The grounded assistant is advisory only. It cannot approve or execute an
  action, and command-like model output is rejected.
- The Windows privileged helper is a **prototype that has not been validated on
  a real Windows host**. Do not enable `CYBERGUARD_DEFENSE_ELEVATION` on a
  production or daily-use machine.
- Real firewall changes require a separate preview, explicit human approval and
  a verified helper installation. `lifetime_minutes` is recorded but does not
  remove a rule automatically.
- Windows Defender, antivirus and Windows Firewall are never disabled by this
  project.
- Always verify findings manually before acting.

Additional documentation:

- [Architecture and trust boundaries](docs/architecture.md)
- [Windows VM testing procedure](docs/windows-vm-testing.md)
- [Measured performance](docs/performance.md)
