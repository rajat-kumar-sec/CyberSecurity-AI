"""Step 4 tests: hybrid retrieval wired into the Flask application.

The endpoint/UI tests monkeypatch ``app.build_context`` so they stay fast and
independent of the optional RAG stack. One end-to-end smoke test exercises the
real retrieval path and skips when it is not usable on this machine.
"""

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
