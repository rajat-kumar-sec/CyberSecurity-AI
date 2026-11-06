from flask import Flask, render_template, request, jsonify
from analyzer import analyze_log
from batch import (
    MAX_UPLOAD_BYTES,
    analyze_text as analyze_text_batch,
    decode_text,
    max_lines as batch_max_lines,
)
from rag.assistant import (
    MAX_QUESTION_CHARS,
    HistoryError,
    explain as explain_analysis,
    normalise_history,
)
from rag.context import DEFAULT_TOP_K, VALID_MODES, build_context

app = Flask(__name__)

MAX_QUERY_CHARS = 4000


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


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    log = ""
    context = None
    summary = None

    if request.method == "POST":

        log = request.form.get("log", "")

        if log.strip():
            result = analyze_log(log)
            context = _context_for(log)
            # Deterministic provider only: page rendering must stay instant.
            summary = _assistant_for(result, context, provider="deterministic")

    return render_template(
        "index.html",
        result=result,
        log=log,
        context=context,
        summary=summary,
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

    if not isinstance(log, str) or not log.strip():
        return jsonify({
            "error": "Log must be a non-empty string."
        }), 400

    result = analyze_log(log)
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

    if not isinstance(log, str) or not log.strip():
        return jsonify({
            "error": "Log must be a non-empty string."
        }), 400

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

    result = analyze_log(log)
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


if __name__ == "__main__":
    app.run(debug=True)
