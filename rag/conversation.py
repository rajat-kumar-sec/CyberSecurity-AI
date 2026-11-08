"""Bounded, in-memory conversation sessions (conversation step 3).

One manager owns isolated conversations across turn boundaries:

* every session has its own bounded message list; nothing is shared,
* modes come from :mod:`rag.prompts` (``companion`` / ``security``), with
  the prompts' safe default when the caller does not choose,
* sessions expire after a configurable TTL and the count is bounded
  (least-recently-active sessions are evicted first),
* history is caller-supplied, **untrusted context**: only ``user`` and
  ``assistant`` roles are accepted (never system/tool), sizes are capped,
  storage offers only defensive copies.

Storage is deliberately process-local: there is no database, no file, no
external service and **no permanent memory** -- restarts, TTL expiry and
``clear``/``end_session`` forget conversations by design. Retrieval and
prompt-building always treat stored turns as context that must never be
obeyed as instructions. No external programs are ever started and nothing
here can approve or perform a defensive action.

Limits are configurable but default to the same bounds as
:mod:`rag.assistant` (newest 8 messages, 2000 chars each, 8000 total).
"""

import secrets
import threading
import time
from dataclasses import dataclass, field

from rag.assistant import (
    MAX_HISTORY_MESSAGE_CHARS,
    MAX_HISTORY_MESSAGES,
    MAX_HISTORY_TOTAL_CHARS,
)
from rag import prompts

DEFAULT_SESSION_TTL_SECONDS = 30 * 60
DEFAULT_MAX_SESSIONS = 100

__all__ = [
    "ROLES",
    "DEFAULT_MAX_SESSIONS",
    "DEFAULT_SESSION_TTL_SECONDS",
    "ConversationError",
    "SessionError",
    "ModeError",
    "InvalidMessageError",
    "ConversationManager",
    "new_session_id",
]

ROLES = ("user", "assistant")


class ConversationError(Exception):
    """Base class for conversation-manager errors."""


class SessionError(ConversationError):
    """Unknown (or expired-and-purged) conversation session."""


class ModeError(ConversationError, ValueError):
    """Conversation mode is not one of the registered prompt modes."""


class InvalidMessageError(ConversationError, ValueError):
    """A caller-supplied message violates a history rule."""


def new_session_id():
    """Unpredictable session identifier (32 hex chars) from ``secrets``."""
    return secrets.token_hex(16)


def _positive_int(name, value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer.")
    return value


@dataclass
class _Session:
    """One isolated conversation (private to this module)."""

    session_id: str
    mode: str
    system_prompt: str
    messages: list = field(default_factory=list)
    created_at: float = 0.0
    last_active: float = 0.0


class ConversationManager:
    """Create, use and expire multiple isolated conversations.

    Parameters
    ----------
    max_sessions : int
        Upper bound on live sessions; the least-recently-active session is
        evicted when the bound is reached (default 100).
    session_ttl_seconds : float
        Inactivity time after which a session is purged and unusable
        (default 1800). Must be positive.
    max_history_messages / max_message_chars / max_total_chars : int
        History bounds, identical in meaning to the ``rag.assistant``
        history budget and sharing its defaults.
    clock : callable, optional
        Zero-argument callable returning the current time (inject a fake
        clock for deterministic TTL tests; default ``time.time``).
    session_id_factory : callable, optional
        Zero-argument callable returning a unique id (default
        :func:`new_session_id`, which uses ``secrets``).

    This manager never touches disk, never calls external services and
    never starts external programs: conversations vanish when the process
    exits. It is session *context*, not permanent memory.
    """

    def __init__(
        self,
        *,
        max_sessions=DEFAULT_MAX_SESSIONS,
        session_ttl_seconds=DEFAULT_SESSION_TTL_SECONDS,
        max_history_messages=MAX_HISTORY_MESSAGES,
        max_message_chars=MAX_HISTORY_MESSAGE_CHARS,
        max_total_chars=MAX_HISTORY_TOTAL_CHARS,
        clock=None,
        session_id_factory=None,
    ):
        self._max_sessions = _positive_int("max_sessions", max_sessions)
        self._max_history_messages = _positive_int(
            "max_history_messages", max_history_messages
        )
        self._max_message_chars = _positive_int(
            "max_message_chars", max_message_chars
        )
        self._max_total_chars = _positive_int(
            "max_total_chars", max_total_chars
        )

        if (
            isinstance(session_ttl_seconds, bool)
            or not isinstance(session_ttl_seconds, (int, float))
            or session_ttl_seconds <= 0
        ):
            raise ValueError(
                "session_ttl_seconds must be a positive number."
            )
        self._ttl = float(session_ttl_seconds)

        self._clock = clock or time.time
        if not callable(self._clock):
            raise ValueError("clock must be callable.")

        self._new_id = session_id_factory or new_session_id
        if not callable(self._new_id):
            raise ValueError("session_id_factory must be callable.")

        self._sessions = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------- creation

    def start_session(self, mode=None):
        """Start a new isolated conversation and return its session id.

        ``mode`` is a :mod:`rag.prompts` mode name (``companion`` or
        ``security``). ``None`` selects the prompts' safe default. Unknown
        modes raise :class:`ModeError` listing the valid names. The mode is
        fixed for the lifetime of the session.
        """
        mode_name, system_prompt = self._resolve_mode(mode)

        with self._lock:
            self._purge_expired()

            # Invalid modes are rejected above, so a bad argument can never
            # evict a healthy session as a side effect.
            while len(self._sessions) >= self._max_sessions:
                self._evict_least_recently_active()

            session_id = self._new_id()
            while session_id in self._sessions:
                session_id = self._new_id()

            now = self._clock()
            self._sessions[session_id] = _Session(
                session_id=session_id,
                mode=mode_name,
                system_prompt=system_prompt,
                messages=[],
                created_at=now,
                last_active=now,
            )

        return session_id

    # ------------------------------------------------------------- reading

    def history(self, session_id):
        """Return a defensive copy of the session's messages.

        Raises :class:`SessionError` for unknown or expired sessions. The
        returned list and its dicts are fresh copies: mutating them cannot
        change stored history.
        """
        with self._lock:
            session = self._live(session_id)
            return self._history_copy(session)

    def describe(self, session_id):
        """Return a full defensive snapshot of a live session."""
        with self._lock:
            session = self._live(session_id)
            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "system_prompt": session.system_prompt,
                "messages": self._history_copy(session),
                "created_at": session.created_at,
                "last_active": session.last_active,
            }

    def mode(self, session_id):
        """Return the registered mode name of a live session."""
        with self._lock:
            return self._live(session_id).mode

    def system_prompt(self, session_id):
        """Return the resolved :mod:`rag.prompts` text for the session."""
        with self._lock:
            return self._live(session_id).system_prompt

    def session_count(self):
        """Number of live (non-expired) sessions right now."""
        with self._lock:
            self._purge_expired()
            return len(self._sessions)

    # ------------------------------------------------------------- writing

    def add_message(self, session_id, role, content):
        """Validate, bound and store one message; return the new history.

        Only ``user``/``assistant`` roles are accepted. Content is trimmed
        and capped per message; the oldest history is dropped when the
        message or total-character budget would be exceeded. Raises
        :class:`InvalidMessageError` before touching any session, and
        :class:`SessionError` for unknown or expired sessions.
        """
        self._validate_message(role, content)

        with self._lock:
            session = self._live(session_id)
            session.messages.append({
                "role": role,
                "content": content.strip()[: self._max_message_chars],
            })
            self._bound_history(session)
            session.last_active = self._clock()
            return self._history_copy(session)

    def clear(self, session_id):
        """Forget the messages but keep the session itself alive."""
        with self._lock:
            session = self._live(session_id)
            session.messages.clear()
            session.last_active = self._clock()

    def end_session(self, session_id):
        """Delete a session outright; it can no longer be used."""
        with self._lock:
            self._purge_expired()
            removed = self._sessions.pop(session_id, None)
            if removed is None:
                raise SessionError(
                    "unknown session: it never existed or it was "
                    "expired/ended."
                )

    # ---------------------------------------------------------------- internals

    @staticmethod
    def _resolve_mode(mode):
        """Validate a mode via rag.prompts; return ``(name, prompt)``."""
        try:
            system_prompt = prompts.get_system_prompt(mode)
        except ValueError as exc:
            raise ModeError(str(exc)) from None
        if mode is None or not str(mode).strip():
            return prompts.DEFAULT_MODE, system_prompt
        return str(mode).strip().lower(), system_prompt

    @staticmethod
    def _validate_message(role, content):
        """Reject anything that is not a user/assistant text turn."""
        if role not in ROLES:
            raise InvalidMessageError(
                f"message role must be 'user' or 'assistant', not {role!r}."
            )
        if not isinstance(content, str) or not content.strip():
            raise InvalidMessageError(
                "message content must be a non-empty string."
            )

    def _live(self, session_id):
        """Return the live session for ``session_id`` or raise
        :class:`SessionError`. Expired sessions are purged first, so they
        can never be resurrected.
        """
        self._purge_expired()
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionError(
                "unknown session: it never existed or it was expired/ended."
            )
        return session

    def _purge_expired(self):
        """Delete sessions idle for longer than the TTL. (Lock held.)"""
        now = self._clock()
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if now - session.last_active > self._ttl
        ]
        for session_id in expired:
            del self._sessions[session_id]

    def _evict_least_recently_active(self):
        """Drop the least-recently-active session to free one slot. (Lock.)"""
        session_id, _ = min(
            self._sessions.items(),
            # Ties resolve in insertion order: the oldest session goes first.
            key=lambda item: item[1].last_active,
        )
        del self._sessions[session_id]

    def _bound_history(self, session):
        """Keep only the newest messages within every budget. (Lock held.)"""
        while len(session.messages) > self._max_history_messages:
            session.messages.pop(0)

        while (
            len(session.messages) > 1
            and sum(len(m["content"]) for m in session.messages)
            > self._max_total_chars
        ):
            session.messages.pop(0)

    def _history_copy(self, session):
        """Defensive copy: fresh list of fresh dicts."""
        return [
            {"role": message["role"], "content": message["content"]}
            for message in session.messages
        ]
