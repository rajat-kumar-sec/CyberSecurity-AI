"""Step 5 tests: grounded assistant context supply and providers.

All tests are offline: the Ollama provider is exercised through an injected
transport, never a real socket.
"""

import pytest

from rag.assistant import (
    DEFAULT_OLLAMA_MODEL,
    MAX_QUESTION_CHARS,
    SYSTEM_PROMPT,
    DeterministicProvider,
    OllamaProvider,
    build_messages,
    citations,
    deterministic_answer,
    explain,
    get_provider,
)

ANALYSIS = {
    "threat_type": "Brute Force",
    "risk": "HIGH",
    "ml_prediction": "Brute Force",
    "ml_confidence": 0.45,
    "username": "admin",
    "source_ip": "10.0.0.5",
    "attempts": 50,
    "findings": ["Possible brute-force attack detected."],
    "recommendations": ["Enable MFA.", "Apply login rate limiting."],
}

PASSAGES = [
    {
        "id": "c1",
        "title": "Brute Force Attack",
        "source_file": "brute_force.txt",
        "category": "Brute Force",
        "section": "Investigation Steps",
        "snippet": "Review authentication logs.",
        "score": 0.5,
        "retrieval_sources": ["bm25", "vector"],
    },
    {
        "id": "c2",
        "title": "Brute Force Attack",
        "source_file": "brute_force.txt",
        "category": "Brute Force",
        "section": "Defensive Measures",
        "snippet": "Enable MFA and rate limiting.",
        "score": 0.4,
        "retrieval_sources": ["bm25"],
    },
]


# ------------------------------------------------------------ prompt building

def test_build_messages_has_system_and_user_roles():
    messages = build_messages(ANALYSIS, PASSAGES, question="What now?")

    assert [m["role"] for m in messages] == ["system", "user"]
    assert messages[0]["content"] == SYSTEM_PROMPT


def test_build_messages_includes_analysis_and_numbered_passages():
    user = build_messages(ANALYSIS, PASSAGES, question="What now?")[1]["content"]

    assert "Brute Force" in user
    assert "HIGH" in user
    assert "45.0% confidence" in user
    assert "KNOWLEDGE PASSAGES" in user
    assert "[1] Brute Force - Investigation Steps" in user
    assert "[2] Brute Force - Defensive Measures" in user
    assert "QUESTION" in user
    assert "What now?" in user


def test_build_messages_without_passes_or_question():
    user = build_messages(ANALYSIS, [], question=None)[1]["content"]

    assert "(none retrieved)" in user
    assert "QUESTION" not in user


def test_build_messages_tolerates_missing_analysis():
    user = build_messages(None, [], question=None)[1]["content"]

    assert "Threat: Unknown" in user
    assert "Risk: UNKNOWN" in user


def test_build_messages_never_includes_conversation_history():
    """Only system + user: nothing is remembered between calls."""
    messages = build_messages(ANALYSIS, PASSAGES, question="q")

    assert len(messages) == 2


# ----------------------------------------------------------------- citations

def test_citations_align_with_prompt_numbering():
    result = citations(PASSAGES)

    assert [c["index"] for c in result] == [1, 2]
    assert result[0]["source_file"] == "brute_force.txt"
    assert result[1]["section"] == "Defensive Measures"
    assert set(result[0]) == {
        "index", "id", "title", "category", "section", "source_file", "score"
    }


def test_citations_handles_empty_and_none():
    assert citations([]) == []
    assert citations(None) == []


# ------------------------------------------------------- deterministic answer

def test_deterministic_answer_is_grounded_and_labelled():
    answer = deterministic_answer(ANALYSIS, PASSAGES)

    assert "Brute Force detected with HIGH risk" in answer
    assert "Possible brute-force attack detected." in answer
    assert "Enable MFA." in answer
    assert "[1] Brute Force - Investigation Steps" in answer
    assert "no language model" in answer


def test_deterministic_answer_includes_question():
    answer = deterministic_answer(ANALYSIS, PASSAGES, question="  What first?  ")

    assert answer.startswith("Question: What first?")


def test_deterministic_answer_without_passages_says_so():
    answer = deterministic_answer(ANALYSIS, [])

    assert "No relevant knowledge passages were retrieved" in answer


def test_deterministic_provider_contract():
    result = DeterministicProvider().answer(ANALYSIS, PASSAGES)

    assert result["provider"] == "deterministic"
    assert result["model"] is None
    assert result["error"] is None
    assert result["answer"]


# ------------------------------------------------------------- provider choice

def test_default_provider_is_deterministic(monkeypatch):
    monkeypatch.delenv("CYBERGUARD_LLM_PROVIDER", raising=False)

    assert isinstance(get_provider(), DeterministicProvider)


def test_unknown_provider_env_falls_back_to_deterministic(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_LLM_PROVIDER", "definitely-not-a-provider")

    assert isinstance(get_provider(), DeterministicProvider)


def test_ollama_provider_selected_from_environment(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("CYBERGUARD_LLM_MODEL", "test-model:1b")

    provider = get_provider()

    assert isinstance(provider, OllamaProvider)
    assert provider.model == "test-model:1b"


def test_ollama_provider_default_model_constant():
    assert DEFAULT_OLLAMA_MODEL


# ------------------------------------------------------------- ollama provider

def test_ollama_provider_sends_grounded_payload():
    captured = {}

    def transport(url, payload, timeout):
        captured["url"] = url
        captured["payload"] = payload
        captured["timeout"] = timeout
        return {"message": {"content": "Check the logs [1]."}}

    provider = OllamaProvider(
        model="test-model", base_url="http://127.0.0.1:9/", transport=transport
    )

    result = provider.answer(ANALYSIS, PASSAGES, question="what now?")

    assert captured["url"] == "http://127.0.0.1:9/api/chat"
    assert captured["payload"]["model"] == "test-model"
    assert captured["payload"]["stream"] is False
    assert captured["payload"]["options"]["num_ctx"] == 2048
    assert captured["payload"]["options"]["temperature"] <= 0.3

    messages = captured["payload"]["messages"]
    assert messages[0]["role"] == "system"
    assert "[1]" in messages[1]["content"]
    assert "what now?" in messages[1]["content"]

    assert result["provider"] == "ollama"
    assert result["answer"] == "Check the logs [1]."
    assert result["model"] == "test-model"


def test_ollama_provider_rejects_empty_response():
    provider = OllamaProvider(transport=lambda *args: {"message": {"content": "  "}})

    with pytest.raises(RuntimeError, match="empty"):
        provider.answer(ANALYSIS, PASSAGES)


def test_ollama_provider_wraps_connection_errors():
    def transport(*args):
        raise OSError("connection refused")

    provider = OllamaProvider(transport=transport)

    with pytest.raises(RuntimeError, match="unavailable"):
        provider.answer(ANALYSIS, PASSAGES)


# ------------------------------------------------------------------- explain

class _BoomProvider:
    name = "ollama"

    def answer(self, *args, **kwargs):
        raise RuntimeError("server down")


def test_explain_defaults_to_deterministic(monkeypatch):
    monkeypatch.delenv("CYBERGUARD_LLM_PROVIDER", raising=False)

    result = explain(ANALYSIS, PASSAGES)

    assert result["provider"] == "deterministic"
    assert result["available"] is True
    assert result["error"] is None
    assert result["grounded_on"] == 2
    assert len(result["citations"]) == 2
    assert result["answer"]


def test_explain_falls_back_when_provider_fails():
    result = explain(ANALYSIS, PASSAGES, question="q", provider=_BoomProvider())

    assert result["provider"] == "deterministic"
    assert result["available"] is True
    assert "server down" in result["error"]
    assert "[1]" in result["answer"]


def test_explain_trims_question_and_keeps_original_text():
    result = explain(ANALYSIS, PASSAGES, question="   why?   ")

    assert result["question"] == "why?"
    assert "Question: why?" in result["answer"]


def test_explain_handles_no_passages():
    result = explain(ANALYSIS, None)

    assert result["grounded_on"] == 0
    assert result["citations"] == []
    assert "No relevant knowledge passages" in result["answer"]


def test_explain_accepts_provider_name():
    result = explain(ANALYSIS, PASSAGES, provider="deterministic")

    assert result["provider"] == "deterministic"


def test_max_question_chars_is_documented():
    assert isinstance(MAX_QUESTION_CHARS, int)
    assert MAX_QUESTION_CHARS > 0
