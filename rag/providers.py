"""LLM provider implementations for the CyberGuard assistant (provider step 1).

Moved out of :mod:`rag.assistant` so the grounding layer (prompt building,
history validation, citations) is decoupled from *how* an answer is produced.

Provider contract
-----------------
A provider is any object with a ``name`` and an ``answer()`` method::

    answer(analysis, passages, question=None, history=None,
           **kwargs) -> {"answer": str, "provider": str,
                         "model": str | None, "error": None}

Providers never talk to the internet except to the configured localhost LLM
server, never import the ``defense`` package, and never approve or execute
anything: security wording and the advisory-only contract are enforced in
:mod:`rag.assistant`, on top of whatever a provider returns.

Registry
--------
``get_provider()`` resolves an explicit name or the ``CYBERGUARD_LLM_PROVIDER``
environment variable. Anything unrecognised resolves to the deterministic
provider, so a bad environment value must never break analysis.
"""

import json
import os
import urllib.error
import urllib.request

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5:1.5b"
DEFAULT_TIMEOUT = 60

PROVIDER_ENV = "CYBERGUARD_LLM_PROVIDER"
MODEL_ENV = "CYBERGUARD_LLM_MODEL"
OLLAMA_URL_ENV = "CYBERGUARD_OLLAMA_URL"

__all__ = [
    "DEFAULT_OLLAMA_MODEL",
    "DEFAULT_OLLAMA_URL",
    "DEFAULT_TIMEOUT",
    "MODEL_ENV",
    "OLLAMA_URL_ENV",
    "PROVIDER_ENV",
    "Provider",
    "DeterministicProvider",
    "OllamaProvider",
    "get_provider",
    "register_provider",
]


def _grounding():
    """Import the grounding layer lazily.

    :mod:`rag.assistant` imports this module at load time (it re-exports the
    provider layer), so importing ``rag.assistant`` at module scope here would
    be a circular import. By the time a provider's ``answer()`` runs, the
    ground module is always fully initialised.
    """
    from rag import assistant

    return assistant


class Provider:
    """Minimal provider contract (see the module docstring)."""

    name = "provider"

    def answer(self, analysis, passages, question=None, history=None,
               **kwargs):
        """Return ``{answer, provider, model, error}`` for one grounded ask."""
        raise NotImplementedError

    def reply(self, messages, **kwargs):
        """Advisory reply over caller-built chat ``messages``.

        ``messages`` is a list of ``{"role", "content"}`` dicts (system
        prompt, earlier turns, current user turn) prepared by the caller
        from :mod:`rag.prompts`. Returns the same result shape as
        :meth:`answer`. Implementations never execute anything and treat
        every message as untrusted content to be rendered as text, never
        as instructions.
        """
        raise NotImplementedError


class DeterministicProvider(Provider):
    """Default provider: instant, offline, no model."""

    name = "deterministic"

    def answer(self, analysis, passages, question=None, history=None, **_):
        return {
            "answer": _grounding().deterministic_answer(
                analysis, passages, question, history=history
            ),
            "provider": self.name,
            "model": None,
            "error": None,
        }

    def reply(self, messages, **_):
        # Honest non-LLM conversation fallback (lives with the assistant
        # layer, next to deterministic_answer).
        return {
            "answer": _grounding().deterministic_chat_reply(messages),
            "provider": self.name,
            "model": None,
            "error": None,
        }


def _post_json(url, payload, timeout):
    """Minimal stdlib JSON POST (no requests dependency)."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


class OllamaProvider(Provider):
    """Optional local-LLM provider talking to an Ollama server on localhost."""

    name = "ollama"

    def __init__(self, model=None, base_url=None, timeout=DEFAULT_TIMEOUT,
                 transport=None):
        self.model = model or os.environ.get(MODEL_ENV) or DEFAULT_OLLAMA_MODEL
        self.base_url = (
            base_url
            or os.environ.get(OLLAMA_URL_ENV)
            or DEFAULT_OLLAMA_URL
        ).rstrip("/")
        self.timeout = timeout
        self._transport = transport or _post_json

    def _complete(self, payload):
        """POST one chat payload to the localhost Ollama endpoint."""
        try:
            data = self._transport(
                f"{self.base_url}/api/chat", payload, self.timeout
            )
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"local model server unavailable at {self.base_url}: {exc}"
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                f"local model server unavailable at {self.base_url}: {exc}"
            ) from exc
        return data

    def _finish(self, data):
        """Validate and safety-filter a model response."""
        content = ((data or {}).get("message") or {}).get("content") or ""
        if not content.strip():
            raise RuntimeError("local model returned an empty response")

        # Output-side safety net (the regex lives with the grounding layer,
        # so every provider returning model prose goes through the same
        # shared filter).
        if _grounding().answer_looks_like_commands(content):
            raise RuntimeError(
                "local model returned command-like content; refusing to show "
                "executable instructions"
            )
        return content.strip()

    def answer(self, analysis, passages, question=None, history=None, **_):
        payload = {
            "model": self.model,
            "messages": _grounding().build_messages(
                analysis, passages, question, history=history
            ),
            "stream": False,
            # Small context window keeps memory use predictable on 8 GB machines.
            "options": {"temperature": 0.2, "num_ctx": 2048},
        }

        content = self._finish(self._complete(payload))
        return {
            "answer": content,
            "provider": self.name,
            "model": self.model,
            "error": None,
        }

    def reply(self, messages, **_):
        """Advisory reply over caller-built messages (conversation mode)."""
        payload = {
            "model": self.model,
            # Copy: a provider must never mutate the caller's history.
            "messages": [dict(message) for message in messages],
            "stream": False,
            # Small context window keeps memory use predictable on 8 GB machines.
            "options": {"temperature": 0.2, "num_ctx": 2048},
        }

        content = self._finish(self._complete(payload))
        return {
            "answer": content,
            "provider": self.name,
            "model": self.model,
            "error": None,
        }


# Fixed registry of known providers. New integrations are added here (or via
# ``register_provider``) instead of by editing rag.assistant. Registry lookups
# are data, not dynamic imports: a name selects an already-imported class.
_PROVIDER_FACTORIES = {
    DeterministicProvider.name: DeterministicProvider,
    OllamaProvider.name: OllamaProvider,
}


def register_provider(name, factory):
    """Register an additional provider factory under a lowercase name."""
    name = str(name or "").strip().lower()
    if not name:
        raise ValueError("provider name must not be empty.")
    if not callable(factory):
        raise TypeError("provider factory must be callable.")

    _PROVIDER_FACTORIES[name] = factory
    return factory


def get_provider(name=None):
    """Resolve a provider from an explicit name or the environment.

    Anything unrecognised resolves to the deterministic provider: a bad
    environment variable must never break analysis.
    """
    name = (name or os.environ.get(PROVIDER_ENV) or "deterministic")
    name = str(name).strip().lower()

    factory = _PROVIDER_FACTORIES.get(name)
    if factory is None:
        return _PROVIDER_FACTORIES["deterministic"]()
    return factory()
