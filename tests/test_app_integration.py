"""Step 4 tests: hybrid retrieval wired into the Flask application.

The endpoint/UI tests monkeypatch ``app.build_context`` so they stay fast and
independent of the optional RAG stack. One end-to-end smoke test exercises the
real retrieval path and skips when it is not usable on this machine.
"""

import io

import pytest

import app as app_module
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def _passage(snippet="Review authentication logs for repeated failures."):
    return {
        "id": "chunk-1",
        "title": "Brute Force Attack",
        "source_file": "brute_force.txt",
        "category": "Brute Force",
        "section": "Investigation Steps",
        "snippet": snippet,
        "score": 0.5,
        "retrieval_sources": ["bm25", "vector"],
    }


def _fake_context(query="q", mode="hybrid", passages=None):
    return {
        "query": query,
        "mode": mode,
        "available": True,
        "passages": [_passage()] if passages is None else passages,
        "truncated": False,
        "error": None,
    }


LOG = ("Failed password for admin from 10.0.0.5 port 22 ssh2: "
       "50 failed attempts for user admin")


# ------------------------------------------------------------ /api/retrieve

def test_api_retrieve_requires_query_field(client):
    response = client.post("/api/retrieve", json={})

    assert response.status_code == 400
    assert response.get_json()["error"] == "Please provide a 'query' field."


@pytest.mark.parametrize("query", ["", "   ", 123, None])
def test_api_retrieve_rejects_invalid_query(client, query):
    response = client.post("/api/retrieve", json={"query": query})

    assert response.status_code == 400
    assert "non-empty" in response.get_json()["error"]


def test_api_retrieve_rejects_overlong_query(client):
    response = client.post(
        "/api/retrieve", json={"query": "a" * (app_module.MAX_QUERY_CHARS + 1)}
    )

    assert response.status_code == 400
    assert "at most" in response.get_json()["error"]


@pytest.mark.parametrize("top_k", [0, 21, -1, "3", 2.5, True])
def test_api_retrieve_validates_top_k(client, top_k):
    response = client.post(
        "/api/retrieve", json={"query": "failed logins", "top_k": top_k}
    )

    assert response.status_code == 400
    assert "top_k" in response.get_json()["error"]


def test_api_retrieve_validates_mode(client):
    response = client.post(
        "/api/retrieve", json={"query": "failed logins", "mode": "magic"}
    )

    assert response.status_code == 400
    assert "mode must be one of" in response.get_json()["error"]


def test_api_retrieve_returns_structured_passages(client, monkeypatch):
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": _fake_context(query, mode),
    )

    response = client.post(
        "/api/retrieve", json={"query": "failed logins", "top_k": 2,
                               "mode": "vector"}
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["available"] is True
    assert body["mode"] == "vector"
    assert body["query"] == "failed logins"
    passage = body["passages"][0]
    assert passage["category"] == "Brute Force"
    assert set(passage) == {
        "id", "title", "source_file", "category", "section",
        "snippet", "score", "retrieval_sources",
    }


# ------------------------------------------------------------- /api/analyze

def test_api_analyze_includes_retrieved_context(client, monkeypatch):
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": _fake_context(query),
    )

    response = client.post("/api/analyze", json={"log": LOG})

    assert response.status_code == 200
    body = response.get_json()
    assert body["threat_type"] == "Brute Force"      # existing behaviour intact
    assert body["retrieved_context"]["available"] is True
    assert body["retrieved_context"]["passages"][0]["section"] == (
        "Investigation Steps"
    )


def test_api_analyze_survives_retrieval_failure(client, monkeypatch):
    def boom(query, top_k=4, mode="hybrid"):
        raise RuntimeError("vector store exploded")

    monkeypatch.setattr(app_module, "build_context", boom)

    response = client.post("/api/analyze", json={"log": LOG})

    assert response.status_code == 200
    body = response.get_json()
    assert body["threat_type"] == "Brute Force"
    assert body["retrieved_context"]["available"] is False
    assert "vector store exploded" in body["retrieved_context"]["error"]
    assert body["retrieved_context"]["passages"] == []


# ------------------------------------------------------------------ dashboard

def test_dashboard_renders_related_knowledge(client, monkeypatch):
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": _fake_context(query),
    )

    response = client.post("/", data={"log": LOG})

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Related Knowledge" in html
    assert "Review authentication logs" in html
    assert "brute_force.txt" in html


def test_dashboard_hides_related_knowledge_without_a_log(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "Related Knowledge" not in response.get_data(as_text=True)


def test_dashboard_hides_related_knowledge_when_retrieval_is_empty(
        client, monkeypatch):
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": _fake_context(query, passages=[]),
    )

    response = client.post("/", data={"log": LOG})

    assert response.status_code == 200
    assert "Related Knowledge" not in response.get_data(as_text=True)


# --------------------------------------------------------- real stack smoke

def test_api_retrieve_against_real_knowledge_base(client):
    """End-to-end: no monkeypatch. Skips when the RAG stack isn't usable."""
    response = client.post(
        "/api/retrieve", json={"query": "someone probing my ports", "top_k": 3}
    )

    assert response.status_code == 200
    body = response.get_json()

    if not body["available"]:
        pytest.skip(f"RAG stack unavailable: {body['error']}")

    assert body["passages"], "ingested knowledge base should return passages"
    assert body["mode"] == "hybrid"
    assert all(
        passage["category"] for passage in body["passages"]
    )


# ----------------------------------------------------------- /api/assistant

def test_api_assistant_requires_log(client):
    response = client.post("/api/assistant", json={})

    assert response.status_code == 400
    assert response.get_json()["error"] == "Please provide a 'log' field."


@pytest.mark.parametrize("log", ["", "   ", 123, None])
def test_api_assistant_rejects_invalid_log(client, log):
    response = client.post("/api/assistant", json={"log": log})

    assert response.status_code == 400
    assert "non-empty" in response.get_json()["error"]


@pytest.mark.parametrize("question", [123, ["q"], {"q": 1}])
def test_api_assistant_rejects_non_string_question(client, question):
    response = client.post(
        "/api/assistant", json={"log": LOG, "question": question}
    )

    assert response.status_code == 400
    assert "Question" in response.get_json()["error"]


def test_api_assistant_rejects_overlong_question(client):
    response = client.post("/api/assistant", json={
        "log": LOG,
        "question": "q" * (app_module.MAX_QUESTION_CHARS + 1),
    })

    assert response.status_code == 400
    assert "at most" in response.get_json()["error"]


def test_api_assistant_rejects_unknown_provider(client):
    response = client.post(
        "/api/assistant", json={"log": LOG, "provider": "openai"}
    )

    assert response.status_code == 400
    assert "provider must be one of" in response.get_json()["error"]


def test_api_assistant_returns_grounded_answer(client, monkeypatch):
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": _fake_context(query),
    )
    monkeypatch.delenv("CYBERGUARD_LLM_PROVIDER", raising=False)

    response = client.post("/api/assistant", json={
        "log": LOG,
        "question": "What should I check first?",
    })
    body = response.get_json()

    assert response.status_code == 200
    assert body["analysis"]["threat_type"] == "Brute Force"
    assert body["retrieved_context"]["available"] is True

    assistant = body["assistant"]
    assert assistant["available"] is True
    assert assistant["provider"] == "deterministic"
    assert assistant["question"] == "What should I check first?"
    assert "Brute Force" in assistant["answer"]
    assert len(assistant["citations"]) == 1
    assert assistant["grounded_on"] == 1


def test_api_assistant_works_without_retrieval(client, monkeypatch):
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": {
            "query": query,
            "mode": "hybrid",
            "available": False,
            "passages": [],
            "truncated": False,
            "error": "vector store missing",
        },
    )
    monkeypatch.delenv("CYBERGUARD_LLM_PROVIDER", raising=False)

    response = client.post("/api/assistant", json={"log": LOG})

    assert response.status_code == 200
    assistant = response.get_json()["assistant"]
    assert assistant["grounded_on"] == 0
    assert assistant["citations"] == []
    assert "No relevant knowledge passages" in assistant["answer"]


def test_api_assistant_survives_assistant_failure(client, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("assistant exploded")

    monkeypatch.setattr(app_module, "explain_analysis", boom)
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": _fake_context(query),
    )

    response = client.post("/api/assistant", json={"log": LOG})

    assert response.status_code == 200
    assistant = response.get_json()["assistant"]
    assert assistant["available"] is False
    assert "assistant exploded" in assistant["error"]


# --------------------------------------------------------- dashboard summary

def test_dashboard_renders_analyst_summary(client, monkeypatch):
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": _fake_context(query),
    )

    response = client.post("/", data={"log": LOG})
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Analyst Summary" in html
    assert "Deterministic summary" in html


def test_dashboard_hides_summary_without_log(client):
    response = client.get("/")

    assert "Analyst Summary" not in response.get_data(as_text=True)


# --------------------------------------------------------------------- chat UI

def test_dashboard_renders_chat_panel(client, monkeypatch):
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": _fake_context(query),
    )

    html = client.post("/", data={"log": LOG}).get_data(as_text=True)

    assert 'id="assistant-chat"' in html
    assert 'id="chat-form"' in html
    assert 'id="chat-question"' in html
    assert "Ask About This Analysis" in html
    assert 'fetch("/api/assistant"' in html
    # Answers are inserted with textContent, never innerHTML.
    assert "bubble.textContent = text" in html


def test_dashboard_hides_chat_panel_without_log(client):
    response = client.get("/")

    assert 'id="assistant-chat"' not in response.get_data(as_text=True)


def test_dashboard_escapes_untrusted_log_in_chat_attribute(client, monkeypatch):
    monkeypatch.setattr(
        app_module, "build_context",
        lambda query, top_k=4, mode="hybrid": _fake_context(query),
    )

    payload = '<script>alert(1)</script> failed login " onload="x'
    html = client.post("/", data={"log": payload}).get_data(as_text=True)

    # Jinja escapes the log inside data-log; the raw tag cannot break out.
    assert "<script>alert(1)" not in html
    assert 'onload="x' not in html

# ---------------------------------------------------------------- /api/batch

BATCH_REPORT = {
    "available": True,
    "filename": "auth.log",
    "lines_total": 3,
    "lines_analyzed": 3,
    "blank_lines": 0,
    "clipped_lines": 0,
    "unique_lines": 3,
    "duplicates_collapsed": 0,
    "truncated": False,
    "limit": 200,
    "max_samples": 50,
    "suspicious": 2,
    "benign": 1,
    "threat_types": [
        {"threat_type": "Brute Force", "count": 1},
        {"threat_type": "Network Scanning", "count": 1},
        {"threat_type": "Unknown", "count": 1},
    ],
    "risks": [
        {"risk": "HIGH", "count": 1},
        {"risk": "MEDIUM", "count": 1},
        {"risk": "LOW", "count": 1},
    ],
    "samples": [],
    "samples_truncated": False,
    "errors": [],
    "error_count": 0,
    "skipped_lines": 0,
    "duration_ms": 12,
    "error": None,
}


def _stub_batch(record=None):
    def stub(text, filename=None):
        result = dict(BATCH_REPORT)
        result["filename"] = filename
        result["text"] = text
        if record is not None:
            record.append((text, filename))
        return result

    return stub


def test_api_batch_requires_a_file_or_content(client):
    response = client.post("/api/batch", json={})

    assert response.status_code == 400
    assert "Upload a file" in response.get_json()["error"]


@pytest.mark.parametrize("content", ["", "   ", 42, None])
def test_api_batch_rejects_invalid_content(client, content):
    response = client.post("/api/batch", json={"content": content})

    assert response.status_code == 400
    assert "non-empty" in response.get_json()["error"]


def test_api_batch_rejects_an_empty_upload(client):
    response = client.post(
        "/api/batch",
        data={"file": (io.BytesIO(b""), "empty.log")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "empty" in response.get_json()["error"]


def test_api_batch_rejects_an_oversized_upload(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_UPLOAD_BYTES", 8)

    response = client.post(
        "/api/batch",
        data={"file": (io.BytesIO(b"x" * 20), "big.log")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "too large" in response.get_json()["error"]


def test_api_batch_rejects_oversized_json_content(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_UPLOAD_BYTES", 8)

    response = client.post("/api/batch", json={"content": "x" * 20})

    assert response.status_code == 400
    assert "too large" in response.get_json()["error"]


def test_api_batch_accepts_an_uploaded_file(client, monkeypatch):
    record = []
    monkeypatch.setattr(app_module, "analyze_text_batch", _stub_batch(record))

    response = client.post(
        "/api/batch",
        data={"file": (io.BytesIO(b"nmap port scan\n"), "auth.log")},
        content_type="multipart/form-data",
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["suspicious"] == 2
    assert body["filename"] == "auth.log"
    assert record == [("nmap port scan\n", "auth.log")]


def test_api_batch_strips_directories_from_the_filename(client, monkeypatch):
    monkeypatch.setattr(app_module, "analyze_text_batch", _stub_batch())

    response = client.post(
        "/api/batch",
        data={"file": (io.BytesIO(b"line"), r"..\..\etc\evil.log")},
        content_type="multipart/form-data",
    )

    name = response.get_json()["filename"]
    assert "/" not in name and "\\" not in name
    assert name.endswith("evil.log")


def test_clean_filename_keeps_only_the_basename():
    assert app_module._clean_filename(r"..\..\etc\evil.log") == "evil.log"
    assert app_module._clean_filename("/var/log/auth.log") == "auth.log"
    assert app_module._clean_filename("   ") is None
    assert app_module._clean_filename(None) is None


def test_api_batch_accepts_json_content(client, monkeypatch):
    monkeypatch.setattr(app_module, "analyze_text_batch", _stub_batch())

    response = client.post(
        "/api/batch",
        json={"content": "nmap port scan", "filename": "scan.txt"},
    )

    assert response.status_code == 200
    assert response.get_json()["filename"] == "scan.txt"


def test_api_batch_rejects_a_file_with_only_blank_lines(client, monkeypatch):
    def stub(text, filename=None):
        report = dict(BATCH_REPORT)
        report.update({"lines_total": 0, "lines_analyzed": 0, "suspicious": 0})
        return report

    monkeypatch.setattr(app_module, "analyze_text_batch", stub)

    response = client.post("/api/batch", json={"content": "x"})

    assert response.status_code == 400
    assert "no non-blank lines" in response.get_json()["error"]


def test_api_batch_survives_an_analyzer_failure(client, monkeypatch):
    def boom(text, filename=None):
        raise RuntimeError("analyzer exploded")

    monkeypatch.setattr(app_module, "analyze_text_batch", boom)

    response = client.post("/api/batch", json={"content": "nmap port scan"})
    body = response.get_json()

    assert response.status_code == 200
    assert body["available"] is False
    assert "analyzer exploded" in body["error"]


def test_api_batch_runs_the_real_analyzer(client):
    content = (
        "Failed password for admin from 10.0.0.5 port 22 ssh2 attempts=20\n"
        "nmap port scan from 10.0.0.9\n"
        "service started successfully\n"
    )

    response = client.post("/api/batch", json={"content": content})
    body = response.get_json()

    assert response.status_code == 200
    assert body["lines_analyzed"] == 3
    assert body["suspicious"] == 2
    assert body["benign"] == 1
    counts = {row["threat_type"]: row["count"] for row in body["threat_types"]}
    assert counts["Brute Force"] == 1
    assert counts["Network Scanning"] == 1
    assert counts["Unknown"] == 1
    assert body["duration_ms"] >= 0


# --------------------------------------------------------- batch panel in UI

def test_dashboard_renders_batch_panel(client):
    html = client.get("/").get_data(as_text=True)

    assert 'id="batch-panel"' in html
    assert 'id="batch-form"' in html
    assert 'id="batch-file"' in html
    assert 'fetch("/api/batch"' in html
    assert "Batch Log File Analysis" in html
    assert "CYBERGUARD_BATCH_MAX_LINES" in html


def test_dashboard_shows_the_batch_line_limit(client, monkeypatch):
    monkeypatch.setattr(app_module, "batch_max_lines", lambda: 42)

    html = client.get("/").get_data(as_text=True)

    assert "first 42 non-blank" in html
