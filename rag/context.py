"""Application-facing retrieval context for CyberGuard AI (Step 4).

This module is the seam between the retrieval layer (``rag.retriever``) and the
Flask application. It exists so ``app.py`` never has to know about BM25,
Chroma, FastEmbed or RRF, and so the application keeps working when the
optional RAG dependencies or the vector store are missing.

Public API::

    build_context(query, top_k=4, max_chars=1200, mode="hybrid")
        -> {query, mode, available, passages, truncated, error}
    format_context(passages) -> str
    get_retriever(mode) -> cached retriever instance

Passages expose only presentation-safe fields::

    {id, title, source_file, category, section, snippet, score,
     retrieval_sources}

No LLM and no chat: this step only surfaces retrieved knowledge alongside the
existing rule/ML analysis. The exact-name knowledge lookup in ``knowledge.py``
is untouched and remains the primary per-threat reference.
"""

DEFAULT_TOP_K = 4
DEFAULT_MAX_CHARS = 1200
VALID_MODES = ("hybrid", "bm25", "vector")

_RETRIEVERS = {}


def get_retriever(mode="hybrid"):
    """Return a cached retriever for ``mode``.

    Raises ``ValueError`` for an unknown mode and ``RuntimeError`` (from
    ``rag.retriever``) when the optional package is missing. Callers that must
    not fail should use :func:`build_context`, which converts both into an
    ``available: False`` result.
    """
    if mode not in VALID_MODES:
        raise ValueError(f"unknown retrieval mode: {mode!r}")

    if mode not in _RETRIEVERS:
        # Imported lazily so importing the Flask app never requires the RAG
        # dependencies to be installed.
        from rag.retriever import BM25Retriever, HybridRetriever, VectorRetriever

        if mode == "bm25":
            _RETRIEVERS[mode] = BM25Retriever()
        elif mode == "vector":
            _RETRIEVERS[mode] = VectorRetriever()
        else:
            _RETRIEVERS[mode] = HybridRetriever()

    return _RETRIEVERS[mode]


def clear_retriever_cache():
    """Drop cached retrievers (used by tests; harmless at runtime)."""
    _RETRIEVERS.clear()


def _empty_context(query, mode):
    return {
        "query": query if isinstance(query, str) else "",
        "mode": mode,
        "available": False,
        "passages": [],
        "truncated": False,
        "error": None,
    }


def _to_passage(hit):
    """Trim an internal retriever hit down to presentation-safe fields."""
    return {
        "id": hit.get("id"),
        "title": hit.get("title", ""),
        "source_file": hit.get("source_file", ""),
        "category": hit.get("category", ""),
        "section": hit.get("section", ""),
        "snippet": hit.get("snippet", ""),
        "score": round(float(hit.get("score", 0.0)), 4),
        "retrieval_sources": list(hit.get("retrieval_sources", [])),
    }


def build_context(
    query,
    top_k=DEFAULT_TOP_K,
    max_chars=DEFAULT_MAX_CHARS,
    mode="hybrid",
    retriever=None,
):
    """Retrieve knowledge passages for ``query``, never raising.

    Returns a dict describing the retrieval attempt. ``available`` is True when
    retrieval ran (even with zero hits) and False when it could not run — for
    example, when the optional dependencies are not installed or the vector
    store is missing.

    ``retriever`` lets tests (and future callers) inject an alternative
    retriever instead of using the cached application one.
    """
    context = _empty_context(query, mode)

    if not isinstance(query, str) or not query.strip():
        return context

    try:
        active = retriever if retriever is not None else get_retriever(mode)
        hits = active.retrieve(query, top_k=top_k) or []
    except Exception as exc:  # missing deps, broken store, unknown mode...
        context["error"] = f"{type(exc).__name__}: {exc}"
        return context

    passages = []
    seen_ids = set()
    used_chars = 0

    for hit in hits:
        chunk_id = hit.get("id")
        if chunk_id in seen_ids:
            continue
        seen_ids.add(chunk_id)

        snippet = hit.get("snippet", "") or ""
        if passages and used_chars + len(snippet) > max_chars:
            context["truncated"] = True
            break

        passages.append(_to_passage(hit))
        used_chars += len(snippet)

        if len(passages) >= top_k:
            break

    context["passages"] = passages
    context["available"] = True
    return context


def format_context(passages):
    """Render passages as a numbered plain-text block.

    Used for console output today and intended as the retrieval context block
    for a future assistant step. Never raises on malformed input.
    """
    lines = []
    for index, passage in enumerate(passages or [], start=1):
        heading = (
            f"[{index}] {passage.get('category', '')} - "
            f"{passage.get('section', '')} "
            f"({passage.get('source_file', '')}, "
            f"score {float(passage.get('score', 0.0)):.4f})"
        )
        lines.append(heading)
        lines.append(passage.get("snippet", ""))
        lines.append("")
    return "\n".join(lines).strip()
