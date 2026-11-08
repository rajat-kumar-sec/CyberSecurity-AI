"""Provider abstraction tests: contract, registry and safe fallback selection.

All tests are offline: the Ollama provider is exercised through an injected
transport, never a real socket. The provider layer must never reference the
``defense`` package or gain any approval/execution capability.
"""

import inspect

import pytest

import rag.assistant as assistant_module
import rag.providers as providers
from rag.providers import (
    DEFAULT_TIMEOUT,
    DeterministicProvider,
    OllamaProvider,
    Provider,
    get_provider,
    register_provider,
)

ANALYSIS = {"threat_type": "Brute Force", "risk": "HIGH"}
PASSAGES = [
    {
        "category": "Brute Force",
        "section": "Investigation Steps",
        "source_file": "brute_force.txt",
        "snippet": "Review authentication logs.",
    },
]
HISTORY = [
    {"role": "user", "content": "What should I check first?"},
    {"role": "assistant", "content": "Review the authentication logs [1]."},
]


# ------------------------------------------------------------------- contract

def test_provider_base_contract_is_abstract():
    provider = Provider()

    assert provider.name == "provider"
    with pytest.raises(NotImplementedError):
        provider.answer(ANALYSIS, PASSAGES)


def test_deterministic_provider_follows_the_result_shape():
    result = DeterministicProvider().answer(ANALYSIS, PASSAGES)

    assert set(result) == {"answer", "provider", "model", "error"}
    assert result["provider"] == "deterministic"
    assert result["model"] is None
    assert result["error"] is None
    assert result["answer"]


def test_deterministic_provider_forwards_question_and_history():
    answer = DeterministicProvider().answer(
        ANALYSIS, PASSAGES, question="And then?", history=HISTORY
    )["answer"]

    assert "Question: And then?" in answer
    assert "Continuing from 2 earlier message(s)" in answer


def test_ollama_provider_uses_the_default_configuration():
    provider = OllamaProvider(model="test-model")

    assert provider.name == "ollama"
    assert provider.model == "test-model"
    assert provider.base_url == "http://127.0.0.1:11434"
    assert provider.timeout == DEFAULT_TIMEOUT
    assert callable(provider._transport)


def test_ollama_provider_sends_grounded_payload_through_the_transport():
    captured = {}

    def transport(url, payload, timeout):
        captured["url"] = url
        captured["payload"] = payload
        captured["timeout"] = timeout
        return {"message": {"content": "Check the logs [1]."}}

    result = OllamaProvider(
        model="test-model", base_url="http://127.0.0.1:9/", transport=transport
    ).answer(ANALYSIS, PASSAGES, question="what now?", history=HISTORY)

    assert captured["url"] == "http://127.0.0.1:9/api/chat"
    assert captured["timeout"] == DEFAULT_TIMEOUT

    messages = captured["payload"]["messages"]
    assert [m["role"] for m in messages] == [
        "system", "user", "assistant", "user",
    ]
    assert "what now?" in messages[-1]["content"]

    assert result == {
        "answer": "Check the logs [1].",
        "provider": "ollama",
        "model": "test-model",
        "error": None,
    }


def test_ollama_provider_rejects_command_like_model_output():
    def transport(url, payload, timeout):
        return {"message": {"content": "Run this:\n```\nwhoami\n```"}}

    provider = OllamaProvider(
        model="test-model", base_url="http://127.0.0.1:9", transport=transport
    )

    with pytest.raises(RuntimeError, match="command-like"):
        provider.answer(ANALYSIS, PASSAGES)


# ------------------------------------------------------------- reply contract

def test_provider_reply_contract_is_abstract():
    with pytest.raises(NotImplementedError):
        Provider().reply([{"role": "user", "content": "hello"}])


def test_deterministic_reply_is_an_honest_non_llm_fallback():
    result = DeterministicProvider().reply(
        [{"role": "user", "content": "tell me a story"}]
    )

    assert set(result) == {"answer", "provider", "model", "error"}
    assert result["provider"] == "deterministic"
    assert result["model"] is None
    assert result["error"] is None
    assert "can't hold a free-form conversation" in result["answer"]
    # Never pretends to be a working conversational partner.
    assert "Once a model is configured" in result["answer"] or \
        "advisory fallback" in result["answer"]


def test_ollama_reply_sends_the_given_messages_unmodified_in_shape():
    captured = {}

    def transport(url, payload, timeout):
        captured["payload"] = payload
        return {"message": {"content": "Sounds like a busy day!"}}

    messages = [
        {"role": "system", "content": "You are a companion."},
        {"role": "user", "content": "hi"},
    ]

    result = OllamaProvider(
        model="test-model", base_url="http://127.0.0.1:9", transport=transport
    ).reply(messages)

    assert captured["payload"]["model"] == "test-model"
    assert captured["payload"]["stream"] is False
    assert captured["payload"]["options"]["num_ctx"] == 2048
    assert captured["payload"]["messages"] == messages
    # The caller's list was not mutated (the provider copies internally).
    assert messages[0]["role"] == "system"
    assert result == {
        "answer": "Sounds like a busy day!",
        "provider": "ollama",
        "model": "test-model",
        "error": None,
    }


def test_ollama_reply_rejects_command_like_output():
    def transport(url, payload, timeout):
        return {"message": {"content": "Just run this:\nnetsh advfirewall set allprofiles state off"}}

    provider = OllamaProvider(
        model="test-model", base_url="http://127.0.0.1:9", transport=transport
    )

    with pytest.raises(RuntimeError, match="command-like"):
        provider.reply([{"role": "user", "content": "hi"}])


def test_ollama_reply_translates_transport_failures():
    def transport(url, payload, timeout):
        raise OSError("connection refused")

    provider = OllamaProvider(
        model="test-model", base_url="http://127.0.0.1:9", transport=transport
    )

    with pytest.raises(RuntimeError, match="unavailable"):
        provider.reply([{"role": "user", "content": "hi"}])


# ------------------------------------------------------------------- registry

def test_get_provider_resolves_names_case_and_whitespace_insensitively():
    assert isinstance(get_provider(" DETERMINISTIC "), DeterministicProvider)
    assert isinstance(get_provider("Ollama"), OllamaProvider)


def test_get_provider_falls_back_to_deterministic_for_unknown_names():
    unknown = get_provider("definitely-not-a-provider")

    assert isinstance(unknown, DeterministicProvider)


def test_get_provider_uses_the_environment(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("CYBERGUARD_LLM_MODEL", "test-model:1b")

    provider = get_provider()

    assert isinstance(provider, OllamaProvider)
    assert provider.model == "test-model:1b"


def test_register_provider_adds_a_selectable_implementation():
    class BoomProvider(Provider):
        name = "boom"

        def answer(self, analysis, passages, question=None, history=None,
                   **kwargs):
            return {
                "answer": "boom",
                "provider": self.name,
                "model": None,
                "error": None,
            }

    try:
        register_provider("boom", BoomProvider)

        provider = get_provider("boom")
    finally:
        providers._PROVIDER_FACTORIES.pop("boom", None)

    assert isinstance(provider, BoomProvider)
    assert providers._PROVIDER_FACTORIES.get("boom") is None


def test_register_provider_validates_input():
    with pytest.raises(ValueError):
        register_provider("   ", DeterministicProvider)

    with pytest.raises(TypeError):
        register_provider("not-callable", "deterministic")


# ------------------------------------------------------------ facade integrity

def test_rag_assistant_reexports_stay_compatible():
    for name in (
        "DEFAULT_OLLAMA_MODEL",
        "DEFAULT_OLLAMA_URL",
        "DEFAULT_TIMEOUT",
        "PROVIDER_ENV",
        "MODEL_ENV",
        "OLLAMA_URL_ENV",
        "Provider",
        "DeterministicProvider",
        "OllamaProvider",
        "get_provider",
    ):
        assert getattr(assistant_module, name) is getattr(providers, name), name


def test_provider_module_never_imports_the_defense_package():
    """The chat/provider surface must have no path to privileged actions."""
    import ast

    source = inspect.getsource(providers)
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert imported <= {"json", "os", "urllib", "rag"}
    assert "defense" not in imported
