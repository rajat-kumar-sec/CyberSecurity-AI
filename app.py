from flask import Flask, render_template, request, jsonify
from analyzer import analyze_log
from rag.assistant import MAX_QUESTION_CHARS, explain as explain_analysis
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


def _assistant_for(result, context, question=None, provider=None):
    """Answer from the analysis plus retrieved passages, never raising.

    ``provider=None`` honours the environment (deterministic by default);
    the dashboard passes ``"deterministic"`` explicitly so page rendering can
    never block on a language model.
    """
    passages = (context or {}).get("passages") or []
    try:
        return explain_analysis(
            result, passages, question=question, provider=provider
        )
    except Exception as exc:
        return {
            "answer": "",
            "provider": "none",
            "model": None,
            "error": f"{type(exc).__name__}: {exc}",
            "available": False,
            "question": question,
            "citations": [],
            "grounded_on": len(passages),
        }


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
        summary=summary
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

    Body: {"log": "...", "question": "optional", "provider": "deterministic"|"ollama"}

    The answer is built from the analysis and the retrieved knowledge passages.
    With the default deterministic provider no model is used; the optional
    ``ollama`` provider talks to a local server only and falls back to the
    deterministic answer when it is unavailable.
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

    result = analyze_log(log)
    context = _context_for(log)
    assistant = _assistant_for(result, context, question=question,
                               provider=provider)

    return jsonify({
        "analysis": result,
        "retrieved_context": context,
        "assistant": assistant,
    })


if __name__ == "__main__":
    app.run(debug=True)
