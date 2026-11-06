"""Step 4 tests: the application-facing retrieval context layer.

These tests use a stub retriever, so they do not need FastEmbed, Chroma or
rank-bm25 to be installed — exactly the property the application relies on.
"""

import pytest

from rag.context import (
    build_context,
    clear_retriever_cache,
    format_context,
    get_retriever,
)


def _hit(chunk_id, snippet="some knowledge text", category="Brute Force",
         section="Investigation Steps", score=0.5,
         sources=("bm25", "vector")):
    return {
        "id": chunk_id,
        "title": "Test Threat",
        "source_file": "brute_force.txt",
        "category": category,
        "section": section,
        "snippet": snippet,
        "score": score,
        "retrieval_sources": list(sources),
        "_rank": 1,
    }


class StubRetriever:
    def __init__(self, hits=None, error=None):
        self.hits = list(hits or [])
        self.error = error
        self.calls = []

    def retrieve(self, query, top_k=5):
        self.calls.append((query, top_k))
        if self.error:
            raise self.error
        return self.hits[:top_k]


# ------------------------------------------------------------- empty queries

@pytest.mark.parametrize("query", [None, "", "   ", "\n\t "])
def test_empty_queries_return_unavailable_context(query):
    context = build_context(query, retriever=StubRetriever())

    assert context["available"] is False
    assert context["passages"] == []
    assert context["error"] is None


def test_non_string_query_is_rejected_without_calling_retriever():
    retriever = StubRetriever([_hit("a")])

    context = build_context(12345, retriever=retriever)

    assert context["available"] is False
    assert context["passages"] == []
    assert retriever.calls == []


# ----------------------------------------------------------------- happy path

def test_successful_retrieval_returns_presentation_fields():
    retriever = StubRetriever([_hit("a")])

    context = build_context("failed logins", retriever=retriever)

    assert context["available"] is True
    assert context["error"] is None
    assert len(context["passages"]) == 1

    passage = context["passages"][0]
    assert set(passage) == {
        "id", "title", "source_file", "category", "section",
        "snippet", "score", "retrieval_sources",
    }
    assert "_rank" not in passage  # internal field never leaks
    assert passage["category"] == "Brute Force"
    assert retriever.calls == [("failed logins", 4)]


def test_top_k_limits_number_of_passages():
    hits = [_hit(f"id{i}") for i in range(10)]

    context = build_context("query", top_k=3, retriever=StubRetriever(hits))

    assert len(context["passages"]) == 3


def test_duplicate_chunk_ids_are_removed():
    hits = [_hit("same"), _hit("same"), _hit("other")]

    context = build_context("query", top_k=5, retriever=StubRetriever(hits))

    ids = [passage["id"] for passage in context["passages"]]
    assert ids == ["same", "other"]


def test_score_is_rounded_for_presentation():
    context = build_context(
        "query", retriever=StubRetriever([_hit("a", score=0.123456789)])
    )

    assert context["passages"][0]["score"] == 0.1235


# ------------------------------------------------------------ char budgeting

def test_char_budget_truncates_and_flags():
    hits = [_hit(f"id{i}", snippet="x" * 100) for i in range(5)]

    context = build_context(
        "query", top_k=5, max_chars=250, retriever=StubRetriever(hits)
    )

    assert len(context["passages"]) == 2
    assert context["truncated"] is True


def test_first_passage_is_kept_even_if_over_budget():
    hits = [_hit("long", snippet="y" * 500)]

    context = build_context(
        "query", top_k=3, max_chars=50, retriever=StubRetriever(hits)
    )

    assert len(context["passages"]) == 1
    assert context["truncated"] is False


# -------------------------------------------------------------- degradation

def test_retriever_error_degrades_to_unavailable():
    retriever = StubRetriever(error=RuntimeError("RAG deps not installed"))

    context = build_context("query", retriever=retriever)

    assert context["available"] is False
    assert context["passages"] == []
    assert "RAG deps not installed" in context["error"]


def test_unknown_mode_degrades_instead_of_raising():
    context = build_context("query", mode="nonsense")

    assert context["available"] is False
    assert context["passages"] == []
    assert "unknown retrieval mode" in context["error"]


def test_get_retriever_rejects_unknown_mode():
    with pytest.raises(ValueError):
        get_retriever("nonsense")


def test_retriever_cache_can_be_cleared():
    clear_retriever_cache()  # must not raise and must leave a usable state
    assert callable(get_retriever)


# ------------------------------------------------------------------ formatting

def test_format_context_includes_metadata_and_text():
    text = format_context([_hit("a", snippet="Review the logs.", score=0.25)])

    assert "[1]" in text
    assert "Brute Force - Investigation Steps" in text
    assert "brute_force.txt" in text
    assert "0.2500" in text
    assert "Review the logs." in text


def test_format_context_numbers_multiple_passages():
    text = format_context([_hit("a"), _hit("b")])

    assert "[1]" in text and "[2]" in text


def test_format_context_empty_is_empty_string():
    assert format_context([]) == ""
    assert format_context(None) == ""
