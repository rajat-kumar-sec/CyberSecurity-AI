import hmac
import json
import os
import secrets
import threading
import time
from urllib.parse import urlsplit

from flask import Flask, g, render_template, request, jsonify
from analyzer import analyze_log
from batch import (
    MAX_UPLOAD_BYTES,
    analyze_text as analyze_text_batch,
    decode_text,
    max_lines as batch_max_lines,
)
from defense.audit import DEFAULT_READ_EVENTS, MAX_READ_EVENTS
from defense.models import DefenseError, PolicyError
from defense.service import DefenseService
from rag.assistant import (
    MAX_QUESTION_CHARS,
    HistoryError,
    explain as explain_analysis,
    normalise_history,
)
from rag.context import DEFAULT_TOP_K, VALID_MODES, build_context

app = Flask(__name__)

# One process-local service. It performs no I/O until an endpoint is used, so
# importing the app stays cheap and side-effect free.
defense_service = DefenseService()

MAX_QUERY_CHARS = 4000
# A single pasted log is bounded well below the global 2 MiB request limit so
# one request cannot pin the CPU inside the rule engine and ML model.
MAX_LOG_CHARS = 50000

# ------------------------------------------------------------ defense safety
# The defensive API is a local approval surface, not a public web API.  It is
# restricted to loopback, strict Host values, same-origin browser requests and
# a session-bound anti-CSRF token.  These controls reduce cross-site request
# forgery and DNS-rebinding risk; they are not a substitute for OS-level
# authentication, which this project does not implement.
DEFENSE_PREFIX = "/api/defense/"
DEFENSE_CSRF_HEADER = "X-CyberGuard-CSRF"
DEFENSE_SESSION_COOKIE = "cg_defense_session"
MAX_DEFENSE_BODY_BYTES = 64 * 1024
DEFENSE_CSRF_TTL_SECONDS = 3600
MAX_DEFENSE_SESSIONS = 64

_CSRF_LOCK = threading.Lock()
_CSRF_SESSIONS = {}

# Keep the global upload limit compatible with the existing batch feature
# (1 MiB) while still bounding every request at the WSGI layer.
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


def _is_loopback_hostname(hostname):
    return (hostname or "").lower() in ("127.0.0.1", "localhost", "::1")


def _request_host_allowed():
    host = (request.host or "").strip().lower()
    if not host:
        return False
    if host.startswith("["):
        # IPv6 literal, e.g. [::1]:5000
        return host == "[::1]" or host.startswith("[::1]:")
    if host.count(":") == 1:
        hostname = host.rsplit(":", 1)[0]
    else:
        hostname = host
    return _is_loopback_hostname(hostname)


def _request_is_loopback():
    remote = request.remote_addr
    return remote in ("127.0.0.1", "::1")


def _origin_allowed(origin):
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if not _is_loopback_hostname(parsed.hostname):
        return False
    return (parsed.netloc or "").lower() == (request.host or "").lower()


def _prune_csrf_locked(now):
    expired = [
        session_id for session_id, (_, expires_at)
        in _CSRF_SESSIONS.items()
        if expires_at <= now
    ]
    for session_id in expired:
        _CSRF_SESSIONS.pop(session_id, None)
    while len(_CSRF_SESSIONS) > MAX_DEFENSE_SESSIONS:
        _CSRF_SESSIONS.pop(next(iter(_CSRF_SESSIONS)))


def _ensure_csrf_session():
    """Return the CSRF token bound to this browser session."""
    if getattr(g, "defense_csrf_token", None):
        return g.defense_csrf_token

    now = time.time()
    session_id = request.cookies.get(DEFENSE_SESSION_COOKIE, "")
    with _CSRF_LOCK:
        _prune_csrf_locked(now)
        record = _CSRF_SESSIONS.get(session_id)
        if record is None or record[1] <= now:
            session_id = secrets.token_urlsafe(32)
            token = secrets.token_urlsafe(32)
            _CSRF_SESSIONS[session_id] = (token, now + DEFENSE_CSRF_TTL_SECONDS)
            g.defense_new_session = True
        else:
            token = record[0]

    g.defense_session_id = session_id
    g.defense_csrf_token = token
    return token


def _csrf_valid():
    expected = _ensure_csrf_session()
    supplied = request.headers.get(DEFENSE_CSRF_HEADER, "")
    if not supplied or not expected:
        return False
    return hmac.compare_digest(expected, supplied)


def _defense_reject(error, category, status):
    return jsonify({"error": error, "error_category": category}), status


@app.before_request
def _defense_request_guard():
    if not request.path.startswith(DEFENSE_PREFIX):
        return None

    if not _request_is_loopback():
        return _defense_reject(
            "The defensive API is restricted to loopback clients.",
            "loopback_required", 403,
        )
    if not _request_host_allowed():
        return _defense_reject(
            "The request Host header is not an allowed loopback host.",
            "host_rejected", 403,
        )

    if request.method in ("GET", "HEAD", "OPTIONS"):
        _ensure_csrf_session()
        return None

    origin = request.headers.get("Origin")
    if origin and not _origin_allowed(origin):
        return _defense_reject(
            "Cross-origin requests are not allowed for the defensive API.",
            "origin_rejected", 403,
        )
    fetch_site = request.headers.get("Sec-Fetch-Site", "").lower()
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return _defense_reject(
            "Cross-site browser requests are not allowed for the defensive "
            "API.",
            "origin_rejected", 403,
        )

    length = request.content_length
    if length is not None and length > MAX_DEFENSE_BODY_BYTES:
        return _defense_reject(
            "The defensive request body is too large.",
            "request_too_large", 413,
        )

    if not _csrf_valid():
        return _defense_reject(
            "A valid session-bound CSRF token is required. Reload the "
            "dashboard and retry.",
            "csrf_required", 403,
        )
    return None


@app.after_request
def _defense_security_headers(response):
    if request.path.startswith(DEFENSE_PREFIX) or request.path == "/":
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )

    if request.path.startswith(DEFENSE_PREFIX) and getattr(
        g, "defense_new_session", False
    ):
        response.set_cookie(
            DEFENSE_SESSION_COOKIE,
            g.defense_session_id,
            httponly=True,
            samesite="Strict",
            secure=False,  # local HTTP loopback; TLS is not part of this app
            max_age=DEFENSE_CSRF_TTL_SECONDS,
            path=DEFENSE_PREFIX,
        )
    return response


def _context_for(query, top_k=DEFAULT_TOP_K, mode="hybrid"):
    """Run retrieval for the UI/API without ever breaking the request.

    rag.context.build_context already degrades gracefully; this wrapper is a
    final guard so a retrieval problem can never turn into a 500 response.
    """
    try:
        return build_context(query, top_k=top_k, mode=mode)
    except Exception as exc:
        return {
            "query": query if isinstance(query, str) else "",
            "mode": mode,
            "available": False,
            "passages": [],
            "truncated": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _assistant_for(result, context, question=None, provider=None, history=None):
    """Answer from the analysis plus retrieved passages, never raising.

    ``provider=None`` honours the environment (deterministic by default);
    the dashboard passes ``"deterministic"`` explicitly so page rendering can
    never block on a language model. ``history`` is optional, caller-owned
    conversation context.
    """
    passages = (context or {}).get("passages") or []
    try:
        return explain_analysis(
            result,
            passages,
            question=question,
            provider=provider,
            history=history,
        )
    except Exception as exc:
        return {
            "answer": "",
            "provider": "none",
            "model": None,
            "error": f"{type(exc).__name__}: {exc}",
            "available": False,
            "question": question,
            "history_used": 0,
            "citations": [],
            "grounded_on": len(passages),
            "advisory_only": True,
            "can_approve": False,
            "can_execute": False,
        }


def _batch_for(text, filename=None):
    """Analyse a log file without letting one bad line fail the request."""
    try:
        return analyze_text_batch(text, filename=filename)
    except Exception as exc:
        return {
            "available": False,
            "filename": filename,
            "lines_total": 0,
            "lines_analyzed": 0,
            "suspicious": 0,
            "benign": 0,
            "threat_types": [],
            "risks": [],
            "samples": [],
            "errors": [],
            "error": f"{type(exc).__name__}: {exc}",
        }


def _clean_filename(name):
    """Keep only a display-safe file name: no directory components."""
    if not isinstance(name, str):
        return None
    name = name.replace("\\", "/").split("/")[-1].strip()
    return name[:120] or None


def _log_input_error(log):
    """Return a user-facing validation error, or None when the log is usable."""
    if not isinstance(log, str) or not log.strip():
        return "Log must be a non-empty string."
    if len(log) > MAX_LOG_CHARS:
        return f"Log must be at most {MAX_LOG_CHARS} characters."
    return None


def _analyze_safely(log):
    """Run the analyzer without letting an internal failure become a 500.

    Returns ``(result, error)``. Details are logged server-side; the caller
    only receives a generic message.
    """
    try:
        return analyze_log(log), None
    except Exception:
        app.logger.exception("Log analysis failed")
        return None, "The analysis could not be completed."


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    log = ""
    context = None
    summary = None
    form_error = None
    analyzed_at = None
    analysis_chars = 0

    if request.method == "POST":

        log = request.form.get("log", "")

        if log.strip():
            error = _log_input_error(log)

            if error:
                form_error = error
            else:
                result, error = _analyze_safely(log)

                if error:
                    form_error = error

            if not form_error and result is not None:
                analysis_chars = len(log)
                analyzed_at = time.strftime(
                    "%Y-%m-%d %H:%M:%S UTC", time.gmtime()
                )
                context = _context_for(log)
                # Deterministic provider only: page rendering must stay instant.
                summary = _assistant_for(
                    result, context, provider="deterministic"
                )

    return render_template(
        "index.html",
        result=result,
        log=log,
        context=context,
        summary=summary,
        form_error=form_error,
        analyzed_at=analyzed_at,
        analysis_chars=analysis_chars,
        batch_limit=batch_max_lines()
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():

    data = request.get_json(silent=True)

    if not data or "log" not in data:
        return jsonify({
            "error": "Please provide a 'log' field."
        }), 400

    log = data["log"]
    error = _log_input_error(log)

    if error:
        return jsonify({"error": error}), 400

    result, error = _analyze_safely(log)

    if error:
        return jsonify({"error": error}), 500

    result["retrieved_context"] = _context_for(log)

    return jsonify(result)


@app.route("/api/retrieve", methods=["POST"])
def api_retrieve():
    """Semantic/keyword knowledge retrieval without running a log analysis.

    Body: {"query": "...", "top_k": 4, "mode": "hybrid"|"bm25"|"vector"}
    """

    data = request.get_json(silent=True)

    if not data or "query" not in data:
        return jsonify({
            "error": "Please provide a 'query' field."
        }), 400

    query = data["query"]

    if not isinstance(query, str) or not query.strip():
        return jsonify({
            "error": "Query must be a non-empty string."
        }), 400

    if len(query) > MAX_QUERY_CHARS:
        return jsonify({
            "error": f"Query must be at most {MAX_QUERY_CHARS} characters."
        }), 400

    top_k = data.get("top_k", DEFAULT_TOP_K)

    if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 20:
        return jsonify({
            "error": "top_k must be an integer between 1 and 20."
        }), 400

    mode = data.get("mode", "hybrid")

    if mode not in VALID_MODES:
        return jsonify({
            "error": f"mode must be one of: {', '.join(VALID_MODES)}."
        }), 400

    return jsonify(_context_for(query, top_k=top_k, mode=mode))


@app.route("/api/assistant", methods=["POST"])
def api_assistant():
    """Grounded question/answer over one log.

    Body: {"log": "...", "question": "optional",
           "provider": "deterministic"|"ollama",
           "history": [{"role": "user"|"assistant", "content": "..."}]}

    The answer is built from the analysis and the retrieved knowledge passages.
    With the default deterministic provider no model is used; the optional
    ``ollama`` provider talks to a local server only and falls back to the
    deterministic answer when it is unavailable.

    ``history`` is optional and caller-owned: the browser sends earlier turns
    only when the user enables the memory toggle. Nothing is stored server-side.
    """

    data = request.get_json(silent=True)

    if not data or "log" not in data:
        return jsonify({
            "error": "Please provide a 'log' field."
        }), 400

    log = data["log"]
    error = _log_input_error(log)

    if error:
        return jsonify({"error": error}), 400

    question = data.get("question")

    if question is not None:
        if not isinstance(question, str):
            return jsonify({
                "error": "Question must be a string."
            }), 400
        if len(question) > MAX_QUESTION_CHARS:
            return jsonify({
                "error": (
                    f"Question must be at most {MAX_QUESTION_CHARS} "
                    "characters."
                )
            }), 400
        question = question.strip() or None

    provider = data.get("provider")

    if provider is not None and provider not in ("deterministic", "ollama"):
        return jsonify({
            "error": "provider must be one of: deterministic, ollama."
        }), 400

    history = data.get("history")

    if history is not None:
        try:
            history = normalise_history(history)
        except HistoryError as exc:
            return jsonify({"error": str(exc)}), 400

    result, error = _analyze_safely(log)

    if error:
        return jsonify({"error": error}), 500

    context = _context_for(log)
    assistant = _assistant_for(
        result, context, question=question, provider=provider, history=history
    )

    return jsonify({
        "analysis": result,
        "retrieved_context": context,
        "assistant": assistant,
    })


@app.route("/api/batch", methods=["POST"])
def api_batch():
    """Analyse a whole log file line by line.

    Accepts either ``multipart/form-data`` with a ``file`` part, or JSON
    ``{"content": "...", "filename": "optional"}``.

    Every line goes through the same analyzer used by ``/api/analyze``, so the
    verdict for a line does not depend on how it was submitted. Very large
    files are truncated at ``CYBERGUARD_BATCH_MAX_LINES`` (default 200) because
    the analyzer runs a model prediction per line; the response reports
    ``truncated`` and ``lines_total`` so the caller knows what was skipped.
    """

    filename = None
    text = None

    if "file" in request.files:
        upload = request.files["file"]
        filename = _clean_filename(upload.filename)
        payload = upload.read(MAX_UPLOAD_BYTES + 1)

        if len(payload) > MAX_UPLOAD_BYTES:
            return jsonify({
                "error": (
                    f"File is too large; the limit is {MAX_UPLOAD_BYTES} "
                    "bytes."
                )
            }), 400

        if not payload:
            return jsonify({"error": "The uploaded file is empty."}), 400

        text = decode_text(payload)

    else:
        data = request.get_json(silent=True)

        if not data or "content" not in data:
            return jsonify({
                "error": (
                    "Upload a file as 'file', or send JSON with a 'content' "
                    "field."
                )
            }), 400

        content = data["content"]

        if not isinstance(content, str) or not content.strip():
            return jsonify({
                "error": "Content must be a non-empty string."
            }), 400

        if len(content.encode("utf-8")) > MAX_UPLOAD_BYTES:
            return jsonify({
                "error": (
                    f"Content is too large; the limit is {MAX_UPLOAD_BYTES} "
                    "bytes."
                )
            }), 400

        text = content
        filename = _clean_filename(data.get("filename"))

    report = _batch_for(text, filename)

    if report.get("available") and not report.get("lines_total"):
        return jsonify({
            "error": "The file contains no non-blank lines."
        }), 400

    return jsonify(report)


# ---------------------------------------------------------------- defense API
# A small, clearly separated surface. There is deliberately no endpoint that
# executes an action from an action_type + params pair: preview creates an
# action id, approval issues a single-use token, and execute needs both.


def _defense_json_object(required=True):
    raw = request.get_data(cache=True)
    if len(raw) > MAX_DEFENSE_BODY_BYTES:
        raise DefenseError(
            "The defensive request body is too large.",
            error_category="request_too_large",
            http_status=413,
        )
    if not raw:
        if required:
            raise PolicyError("Send a JSON object.")
        return {}

    try:
        text = raw.decode("utf-8")
        data = json.loads(
            text,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite {value}")
            ),
        )
    except (UnicodeDecodeError, ValueError):
        raise PolicyError(
            "Send a well-formed JSON object (NaN and Infinity are rejected)."
        ) from None

    if not isinstance(data, dict):
        raise PolicyError("Send a JSON object.")
    return data


def _defense_handle(call):
    try:
        return call()
    except DefenseError as exc:
        return jsonify(exc.to_dict()), exc.http_status
    except Exception:
        # Never leak a traceback to the browser; the log keeps the detail.
        app.logger.exception("Unexpected defensive-action failure")
        return jsonify({
            "error": "Internal defensive-action error.",
            "error_category": "internal_error",
        }), 500


@app.route("/api/defense/status", methods=["GET"])
def api_defense_status():
    """Capabilities, platform, elevation state and the CSRF bootstrap token."""
    def run():
        data = defense_service.status()
        data["csrf_token"] = _ensure_csrf_session()
        data["csrf_header"] = DEFENSE_CSRF_HEADER
        data["security"] = {
            "loopback_only": True,
            "host_validation": True,
            "origin_validation": True,
            "csrf_required": True,
            "max_body_bytes": MAX_DEFENSE_BODY_BYTES,
        }
        return jsonify(data)

    return _defense_handle(run)


@app.route("/api/defense/inspect", methods=["POST"])
def api_defense_inspect():
    """Run one read-only inspection. State-changing types are rejected."""
    def run():
        data = _defense_json_object()
        params = data.get("params", {})
        if not isinstance(params, dict):
            raise PolicyError("params must be a JSON object.")
        return jsonify(defense_service.inspect(data.get("action_type"), params))

    return _defense_handle(run)


@app.route("/api/defense/actions/preview", methods=["POST"])
def api_defense_preview():
    """Validate parameters and return an exact, non-executed preview."""
    def run():
        data = _defense_json_object()
        params = data.get("params", {})
        if not isinstance(params, dict):
            raise PolicyError("params must be a JSON object.")
        return jsonify(
            defense_service.preview(data.get("action_type"), params)
        ), 201

    return _defense_handle(run)


@app.route(
    "/api/defense/actions/<action_id>/approve", methods=["POST"]
)
def api_defense_approve(action_id):
    """Explicitly approve one prepared action.

    ``confirm`` must equal the exact action type. The response contains the
    single-use token exactly once; it is never written to the audit log.
    """
    def run():
        data = _defense_json_object()
        return jsonify(defense_service.approve(action_id, data.get("confirm")))

    return _defense_handle(run)


@app.route(
    "/api/defense/actions/<action_id>/execute", methods=["POST"]
)
def api_defense_execute(action_id):
    """Execute one approved action exactly once.

    Only the action id and the approval token are accepted. There is no
    ``approved`` boolean and no way to supply new parameters here.
    """
    def run():
        data = _defense_json_object(required=False)
        return jsonify(
            defense_service.execute(action_id, data.get("approval_token"))
        )

    return _defense_handle(run)


@app.route(
    "/api/defense/actions/<action_id>/cancel", methods=["POST"]
)
def api_defense_cancel(action_id):
    """Cancel a pending action and revoke its approval."""
    return _defense_handle(
        lambda: jsonify(defense_service.cancel(action_id))
    )


@app.route(
    "/api/defense/actions/<action_id>/rollback", methods=["POST"]
)
def api_defense_rollback(action_id):
    """Prepare (never execute) the inverse of a completed action."""
    return _defense_handle(
        lambda: (jsonify(defense_service.prepare_rollback(action_id)), 201)
    )


@app.route("/api/defense/audit", methods=["GET"])
def api_defense_audit():
    """Read-only audit history, newest first. No write/delete endpoint."""
    def run():
        raw = request.args.get("limit", str(DEFAULT_READ_EVENTS))
        try:
            limit = int(raw)
        except (TypeError, ValueError):
            raise PolicyError(
                "limit must be an integer between 1 and "
                f"{MAX_READ_EVENTS}."
            ) from None
        if not 1 <= limit <= MAX_READ_EVENTS:
            raise PolicyError(
                f"limit must be between 1 and {MAX_READ_EVENTS}."
            )
        return jsonify(defense_service.audit_events(limit))

    return _defense_handle(run)


if __name__ == "__main__":
    # Never bind the approval surface to a public interface by accident.
    # Debug mode is off by default; set CYBERGUARD_DEBUG=1 for local debugging.
    debug = os.environ.get("CYBERGUARD_DEBUG", "").strip().lower() in (
        "1", "true", "yes", "on"
    )
    configured_host = os.environ.get("CYBERGUARD_HOST", "127.0.0.1")
    if configured_host not in ("127.0.0.1", "localhost", "::1"):
        # The approval surface is loopback-only.  A public bind would be an
        # accidental exposure even though the defense routes would reject it.
        configured_host = "127.0.0.1"
    app.run(
        host=configured_host,
        port=int(os.environ.get("CYBERGUARD_PORT", "5000")),
        debug=debug,
    )
