"""Step 3 tests: BM25, vector and hybrid retrieval, plus evaluation metrics.

Strategy:
  - Tokenizer, BM25 and metric tests run on a tiny synthetic corpus (no
    heavy behavior needed).
  - Vector and hybrid tests reuse the real FastEmbed/Chroma stack and skip
    (instead of fail) only when the optional packages aren't installed.
"""

import pytest

pytest.importorskip("fastembed", reason="RAG deps not installed")
pytest.importorskip("chromadb", reason="RAG deps not installed")

from rag.retriever import (
    BM25Retriever,
    HybridRetriever,
    VectorRetriever,
    make_snippet,
    retrieve,
    tokenize,
)


def _chunk(chunk_id, text, category="Brute Force", section="Description",
           title="T", source_file="kb.txt"):
    return {
        "id": chunk_id,
        "text": text,
        "metadata": {
            "title": title,
            "source_file": source_file,
            "category": category,
            "section": section,
        },
    }


CORPUS = [
    _chunk("a1", "Brute Force attack - Description: repeated failed logins "
                 "at guessing passwords", category="Brute Force"),
    _chunk("a2", "Brute Force attack - Defensive Measures: enable MFA, "
                 "rate limiting and account lockout", category="Brute Force",
           section="Defensive Measures"),
    _chunk("m1", "Malware indicators: unexpected processes, encrypted files, "
                 "ransom note", category="Malware"),
    _chunk("n1", "Network scanning indicators: connections to many ports, "
                 "nmap probing hosts", category="Network Scanning"),
    _chunk("s1", "SQL injection: UNION SELECT in query strings, database "
                 "errors", category="SQL Injection"),
]


# ---------------------------------------------------------------- tokenizer

def test_tokenize_splits_words_and_lowercases():
    assert tokenize("Failed-Login: UNION=SELECT!") == [
        "failed", "login", "union", "select"
    ]


def test_tokenize_empty():
    assert tokenize("!!!") == []
    assert tokenize("") == []


def test_snippet_normalizes_and_truncates():
    long = "word " * 100
    snippet = make_snippet(long, max_chars=50)
    assert len(snippet) <= 50
    assert snippet.endswith("...")
    assert make_snippet("a\n  b\t c") == "a b c"


# ------------------------------------------------------------------- bm25

def test_bm25_ranks_exact_keyword_query_first():
    retriever = BM25Retriever(chunks=CORPUS)
    results = retriever.retrieve("nmap ports scanning", top_k=3)

    assert results[0]["id"] == "n1"
    assert all(r["retrieval_sources"] == ["bm25"] for r in results)


def test_bm25_prefers_section_when_named():
    retriever = BM25Retriever(chunks=CORPUS)
    results = retriever.retrieve("defensive measures lockout MFA", top_k=2)

    assert results[0]["id"] == "a2"
    assert results[0]["section"] == "Defensive Measures"


def test_bm25_empty_query_returns_empty():
    retriever = BM25Retriever(chunks=CORPUS)
    assert retriever.retrieve("", top_k=3) == []
    assert retriever.retrieve("   ", top_k=3) == []


def test_bm25_handles_non_matching_query_without_errors():
    retriever = BM25Retriever(chunks=CORPUS)
    results = retriever.retrieve("zzzzqqqq", top_k=2)
    assert isinstance(results, list)


def test_bm25_empty_corpus_returns_empty():
    retriever = BM25Retriever(chunks=[])
    assert retriever.retrieve("anything", top_k=3) == []


def test_bm25_metadata_preserved():
    retriever = BM25Retriever(chunks=CORPUS)
    result = retriever.retrieve("ransomware ransom note", top_k=1)[0]

    assert set(result) >= {"title", "source_file", "category", "section",
                           "snippet", "score"}
    assert result["category"] == "Malware"
    assert result["source_file"] == "kb.txt"


def test_bm25_top_k_honored():
    retriever = BM25Retriever(chunks=CORPUS)
    assert len(retriever.retrieve("attack measures select ports process", top_k=2)) == 2
    assert len(retriever.retrieve("attack", top_k=1)) == 1


# ------------------------------------------------------------------ vector

def test_vector_ranks_and_returns_results():
    retriever = VectorRetriever(store_path="data/vectorstore")
    if not retriever.is_available():
        pytest.skip("vector store not ingested on this machine yet")

    results = retriever.retrieve("how do I investigate repeated failed logins", top_k=3)

    assert results, "ingested vector store should return results"
    assert results[0]["_rank"] == 1
    ids = [r["id"] for r in results]
    assert len(ids) == len(set(ids))


def test_vector_scores_are_similarity_not_distance():
    retriever = VectorRetriever(store_path="data/vectorstore")
    if not retriever.is_available():
        pytest.skip("vector store not ingested on this machine yet")

    results = retriever.retrieve("failed login attempts", top_k=1)

    assert 0.0 <= results[0]["score"] <= 1.0


def test_vector_unavailable_store_returns_empty(tmp_path):
    retriever = VectorRetriever(store_path=tmp_path / "does_not_exist")
    assert retriever.is_available() is False
    assert retriever.retrieve("anything", top_k=3) == []


def test_vector_empty_query_returns_empty():
    retriever = VectorRetriever(store_path="data/vectorstore")
    assert retriever.retrieve("", top_k=3) == []


def test_vector_metadata_preserved():
    retriever = VectorRetriever(store_path="data/vectorstore")
    if not retriever.is_available():
        pytest.skip("vector store not ingested on this machine yet")

    result = retriever.retrieve("nmap port scan", top_k=1)[0]

    assert set(result) >= {"title", "source_file", "category", "section",
                           "snippet", "score"}
    assert result["retrieval_sources"] == ["vector"]


# ------------------------------------------------------------------ hybrid

def _stub_ranker(ranking, tag):
    """Stand-in retriever returning pre-set structured rankings."""

    class _Stub:
        def retrieve(self, query, top_k=5):
            return [
                {**payload, "_rank": rank, "retrieval_sources": [tag]}
                for rank, payload in enumerate(ranking[:max(top_k, 0)], start=1)
            ]

    return _Stub()


def _stub_hit(chunk_id, category):
    return {
        "id": chunk_id,
        "title": "T",
        "source_file": "kb.txt",
        "category": category,
        "section": "Description",
        "snippet": "snippet for " + chunk_id,
        "score": 1.0,
    }


def test_hybrid_fuses_both_rankings():
    hybrid = HybridRetriever(
        bm25=_stub_ranker([_stub_hit("a1", "Brute Force"),
                           _stub_hit("n1", "Network Scanning")], "bm25"),
        vector=_stub_ranker([_stub_hit("n1", "Network Scanning"),
                             _stub_hit("a1", "Brute Force")], "vector"),
        rrf_k=60,
    )
    results = hybrid.retrieve("anything", top_k=2)

    # Ranks complement: id0 = 1st in bm25/2nd in vector, id1 = vice versa.
    assert {r["id"] for r in results} == {"a1", "n1"}
    assert all(set(r["retrieval_sources"]) == {"bm25", "vector"} for r in results)


def test_hybrid_weight_changes_fusion_order():
    hybrid = HybridRetriever(
        bm25=_stub_ranker([_stub_hit("a1", "Brute Force"),
                           _stub_hit("n1", "Network Scanning")], "bm25"),
        vector=_stub_ranker([_stub_hit("n1", "Network Scanning"),
                             _stub_hit("a1", "Brute Force")], "vector"),
        rrf_k=60, bm25_weight=2.0, vector_weight=1.0,
    )
    results = hybrid.retrieve("anything", top_k=2)

    assert results[0]["id"] == "a1"  # higher bm25 weight favors bm25's #1


def test_hybrid_dedupes_on_id():
    hybrid = HybridRetriever(
        bm25=_stub_ranker([_stub_hit("a1", "Brute Force")], "bm25"),
        vector=_stub_ranker([_stub_hit("a1", "Brute Force")], "vector"),
    )
    results = hybrid.retrieve("anything", top_k=5)

    assert len(results) == 1
    assert set(results[0]["retrieval_sources"]) == {"bm25", "vector"}


def test_hybrid_empty_query_returns_empty():
    hybrid = HybridRetriever(
        bm25=_stub_ranker([_stub_hit("a1", "Brute Force")], "bm25"),
        vector=_stub_ranker([_stub_hit("a1", "Brute Force")], "vector"),
    )
    assert hybrid.retrieve("", top_k=3) == []
    assert hybrid.retrieve("   ", top_k=3) == []


def test_hybrid_top_k_and_deterministic_rrf_order():
    hits = [_stub_hit(f"id{i}", "Brute Force") for i in range(5)]
    # Deliberately non-symmetric ordering so RRF sums are tie-free:
    # id1: bm25#2 + vec#1, id0: bm25#1 + vec#3, id3: bm25#4 + vec#2...
    hybrid = HybridRetriever(
        bm25=_stub_ranker(hits, "bm25"),
        vector=_stub_ranker(
            [hits[1], hits[3], hits[0], hits[4], hits[2]], "vector"
        ),
        candidates_per_retriever=5,
    )
    results = hybrid.retrieve("anything", top_k=3)

    assert len(results) == 3
    assert [r["id"] for r in results] == ["id1", "id0", "id3"]


def test_hybrid_rrf_scores_match_formula():
    hybrid = HybridRetriever(
        bm25=_stub_ranker([_stub_hit("a1", "Brute Force")], "bm25"),
        vector=_stub_ranker([_stub_hit("a1", "Brute Force")], "vector"),
        rrf_k=60, bm25_weight=1.0, vector_weight=1.0,
    )
    result = hybrid.retrieve("anything", top_k=1)[0]

    assert result["score"] == pytest.approx(2 * (1.0 / (60 + 1)), abs=1e-9)


def test_hybrid_reports_single_source_when_one_retriever_is_empty():
    hybrid = HybridRetriever(
        bm25=_stub_ranker([_stub_hit("a1", "Brute Force")], "bm25"),
        vector=_stub_ranker([], "vector"),
    )
    results = hybrid.retrieve("anything", top_k=2)

    assert results[0]["retrieval_sources"] == ["bm25"]


def test_hybrid_structured_result_contract():
    hybrid = HybridRetriever(
        bm25=_stub_ranker([_stub_hit("a1", "Brute Force")], "bm25"),
        vector=_stub_ranker([_stub_hit("a1", "Brute Force")], "vector"),
    )
    result = hybrid.retrieve("anything", top_k=1)[0]

    assert set(result) >= {"title", "source_file", "category", "section",
                           "snippet", "score", "retrieval_sources"}


def test_retrieve_dispatcher_validates_mode():
    with pytest.raises(ValueError):
        retrieve("query", mode="nonsense")


# ------------------------------------------------------------------ metrics

def _hit(category):
    return {"id": "x", "title": "t", "source_file": "f", "category": category,
            "section": "s", "snippet": "n", "score": 0.5,
            "retrieval_sources": ["bm25"]}


def _eval_queries():
    return [
        {"id": "q1", "query": "a", "expected_categories": ["Brute Force"]},
        {"id": "q2", "query": "b", "expected_categories": ["Malware"]},
    ]


def _fn_for(rankings):
    def fn(query, top_k):
        idx = 0 if query == "a" else 1
        return list(rankings[idx])[:top_k]
    return fn


def test_metrics_perfect_case():
    from rag.evaluate import evaluate_queries

    report = evaluate_queries(_eval_queries(), _fn_for([
        [_hit("Brute Force")],
        [_hit("Malware")],
    ]))
    assert report["recall_at_3"] == 1.0
    assert report["recall_at_5"] == 1.0
    assert report["mrr"] == 1.0


def test_metrics_mrr_counts_first_relevant_rank():
    from rag.evaluate import evaluate_queries

    report = evaluate_queries(_eval_queries(), _fn_for([
        [_hit("Malware"), _hit("Brute Force")],                    # rank 2
        [_hit("Brute Force"), _hit("Brute Force"), _hit("Malware")],  # rank 3
    ]))
    assert report["mrr"] == pytest.approx((0.5 + 1.0 / 3.0) / 2.0)
    assert report["recall_at_3"] == 1.0


def test_metrics_counts_misses_as_zero():
    from rag.evaluate import evaluate_queries

    report = evaluate_queries(_eval_queries(), _fn_for([
        [_hit("Malware"), _hit("Malware")],   # q1: never relevant (Brute Force expected)
        [_hit("Brute Force"), _hit("Malware")],  # q2: Malware hit at rank 2
    ]))
    assert report["recall_at_3"] == 0.5
    assert report["recall_at_5"] == 0.5
    assert report["mrr"] == pytest.approx(0.25)  # (0 + 1/2) / 2 queries


def test_metrics_handle_empty_result_lists():
    from rag.evaluate import evaluate_queries

    report = evaluate_queries(_eval_queries(), _fn_for([[], []]))
    assert report["recall_at_3"] == 0.0
    assert report["recall_at_5"] == 0.0
    assert report["mrr"] == 0.0
