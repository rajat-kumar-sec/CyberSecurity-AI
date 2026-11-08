# CyberGuard AI — Architecture

CyberGuard AI is a **local, single-user defensive assistant**. It is not a
service, not an enterprise EDR and not an antivirus replacement. The diagram
below shows the actual module boundaries in this repository.

## System overview

```mermaid
flowchart TB
    User["Analyst<br/>(browser on the local machine)"]

    subgraph Web["Flask application (normal user, loopback only)"]
        UI["Dashboard<br/>templates/index.html"]
        API["REST API<br/>/api/analyze · /api/retrieve<br/>/api/assistant · /api/batch"]
        DEF["Defense API<br/>/api/defense/*<br/>loopback + Host + Origin + CSRF"]
    end

    subgraph Core["Analysis core"]
        AN["analyzer.py<br/>rule engine + ML fusion"]
        ML["models/threat_classifier.joblib<br/>TF-IDF + calibrated LogReg"]
        KB["knowledge.py<br/>exact threat reference"]
        BA["batch.py<br/>bounded line-by-line analysis"]
    end

    subgraph RAG["Optional retrieval layer (rag/)"]
        CH["chunker.py"]
        EM["embedder.py<br/>FastEmbed MiniLM"]
        VS[("Chroma vector store<br/>data/vectorstore (git-ignored)")]
        RT["retriever.py<br/>BM25 + vector + RRF"]
        CTX["context.py"]
        AS["assistant.py<br/>deterministic + optional Ollama"]
    end

    subgraph Defense["Defense subsystem (defense/)"]
        POL["policy.py<br/>fail-closed validation"]
        APP["approvals.py<br/>bounded stores + rate limit"]
        EXE["executor.py<br/>preview → approve → execute"]
        AUD["audit.py<br/>append-only JSONL"]
        REG["registry.py<br/>fixed allowlist"]
        RB["rollback.py<br/>inverse-action preparation"]
        SVC["service.py"]
    end

    subgraph Windows["Windows-only layer (lazily imported)"]
        INS["inspection.py<br/>fixed tasklist / netstat / netsh reads"]
        FW["firewall.py<br/>fixed netsh argv + ownership registry"]
        ELEV["elevated.py<br/>one-shot HMAC helper"]
        FWALL[("Windows Firewall<br/>CyberGuard- rules only")]
    end

    OLL["Optional Ollama server<br/>127.0.0.1:11434"]

    User --> UI
    User --> API
    User --> DEF
    UI --> AN
    UI --> BA
    UI --> RAG
    UI --> DEF
    API --> AN
    API --> RAG
    API --> BA
    AN --> ML
    AN --> KB
    RAG --> CH
    CH --> EM
    EM --> VS
    RT --> VS
    CTX --> RT
    AS --> CTX
    AS -. optional .-> OLL
    DEF --> SVC
    SVC --> POL
    SVC --> APP
    SVC --> EXE
    SVC --> AUD
    SVC --> RB
    EXE --> REG
    EXE --> INS
    EXE --> ELEV
    EXE --> FW
    ELEV --> FW
    FW --> FWALL
    INS -. read-only .-> FWALL

    classDef untrusted fill:#3a1f1f,stroke:#c0392b,color:#fff;
    classDef trusted fill:#1f3a2a,stroke:#27ae60,color:#fff;
    class OLL untrusted;
    class ELEV,FW trusted;
```

## Request paths

### 1. Log analysis

```mermaid
sequenceDiagram
    participant B as Browser
    participant F as Flask app.py
    participant A as analyzer.py
    participant M as ML model
    participant K as knowledge.py
    participant R as rag/context.py

    B->>F: POST / (form) or POST /api/analyze
    F->>F: validate log (non-empty, <= 50,000 chars)
    F->>A: analyze_log(log)
    A->>M: predict + predict_proba
    A->>A: rule engine + evidence extraction
    A->>K: exact threat reference
    F->>R: build_context(log)
    R-->>F: passages, or available=false
    F-->>B: threat, risk, evidence, ML, knowledge, passages
```

The ML prediction is **probabilistic** and is shown as one signal, not as
confirmation. Risk is a rule-based triage label.

### 2. Assistant question

```mermaid
sequenceDiagram
    participant B as Browser
    participant F as Flask app.py
    participant R as retrieval
    participant AS as rag/assistant.py
    participant O as Ollama (optional)

    B->>F: POST /api/assistant {log, question, history?}
    F->>F: analyze_log(log)
    F->>R: build_context(log)
    F->>AS: explain(analysis, passages, question, history)
    alt provider = ollama
        AS->>O: grounded prompt
        O-->>AS: answer or error
        AS->>AS: reject command-like output
    else deterministic (default)
        AS->>AS: compose grounded answer
    end
    AS-->>F: answer + citations + advisory flags
    F-->>B: analysis + retrieved_context + assistant
```

The assistant has no tools, no approval capability and no execution path. Its
result explicitly reports `advisory_only: true`, `can_approve: false` and
`can_execute: false`.

### 3. Defensive action (state-changing)

```mermaid
sequenceDiagram
    participant B as Browser
    participant F as Flask /api/defense
    participant S as DefenseService
    participant P as policy.py
    participant S2 as ApprovalStore
    participant E as Executor
    participant H as Elevated helper (optional)
    participant W as Windows Firewall

    B->>F: POST /actions/preview
    F->>S: preview(action_type, params)
    S->>P: validate + canonicalise
    S-->>B: action_id + exact preview (no change)
    B->>F: POST /actions/{id}/approve {confirm}
    F->>S2: issue single-use, expiring token
    S2-->>B: token (once)
    B->>F: POST /actions/{id}/execute {approval_token}
    F->>E: execute
    E->>S2: consume token atomically
    alt elevation disabled or helper untrusted
        E-->>B: elevation_disabled / helper_untrusted
    else helper trusted and elevation enabled
        E->>H: signed one-shot request via UAC
        H->>P: revalidate canonical parameters
        H->>W: fixed netsh argv
        H-->>E: signed result
        E->>E: verify exact rule properties
        E-->>B: success / unverified / execution_unknown / failure
    end
    E->>E: append sanitized audit event
```

There is deliberately no endpoint that executes an action from an
`action_type` + `params` pair. Preview, approval and execution are separate
requests, and the approval token is never rendered in the UI or written to the
audit log.

## Trust boundaries

| Boundary | What is trusted | What is not |
| --- | --- | --- |
| Browser → Flask | Loopback client, strict Host, same-origin, session CSRF | Any remote client; cross-site requests |
| Log / knowledge text | Nothing — rendered with `textContent` / Jinja autoescape | Any HTML or script in the input |
| Assistant | Deterministic grounded composer | The LLM: no tools, no approval, command-like output rejected |
| Defense API | Canonical parameters produced by `policy.py` | Arbitrary action types, extra keys, client-supplied rule names |
| Elevated helper | Administrator-protected helper root + verified ACL | Repository checkout, ordinary venv, bare path |
| Windows commands | Fixed argv lists via trusted `System32` paths | Shell strings, PATH lookup, user-supplied executables |
| Audit log | Append-only through the app | Tamper-proof storage (same-user/admin can edit) |

## Failure behaviour

- Missing RAG dependencies or vector store → retrieval `available: false`; the
  rest of the analysis still works.
- Ollama unavailable, slow or malformed → deterministic answer, with the reason
  recorded in `assistant.error`.
- LLM answer that looks like a shell command → refused; deterministic answer
  returned.
- Analyzer failure → generic 500 for the API, an inline error on the dashboard;
  no traceback is returned to the browser.
- Elevation disabled or helper untrusted → fail closed with a stable error
  category.
- Timeout during elevated execution → `execution_unknown`; never success and
  never retried automatically.
- Corrupt rule ownership registry → fail closed and report it; never silently
  replaced.

## Related documents

- [Windows VM testing procedure](windows-vm-testing.md)
- [Performance measurements](performance.md)
