"""Retrieval-quality evaluation for the RAG retrievers (Step 3).

Measures Recall@3, Recall@5 and MRR for each retrieval mode over the curated
dataset at data/eval/retrieval_eval.json, plus per-query diagnostics for
failure analysis.

Definitions (documented in the dataset too):
  Recall@k = fraction of queries with at least one expected category among
             the top-k retrieved results (any-order set membership).
  MRR      = mean of 1/rank of the first top-5 result whose category is
             expected; rank 0 (no hit inside top 5) contributes 0.

Run from the repo root:
    python -m rag.evaluate
"""

import json
from pathlib import Path

from rag.retriever import BM25Retriever, HybridRetriever, VectorRetriever

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "data" / "eval" / "retrieval_eval.json"

TOP_K = 5
MRR_MAX_RANK = 5


def load_dataset(path=None):
    path = Path(path) if path else DATASET_PATH
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["queries"]


def _is_relevant_category(result, expected_categories):
    return result["category"] in expected_categories


def evaluate_queries(queries, retrieval_fn, top_k=TOP_K):
    """Evaluate one retrieval_fn(query, top_k) -> list of results.

    Returns aggregate metrics plus per-query diagnostics.
    """
    recall_at_3_hits = 0
    recall_at_5_hits = 0
    reciprocal_ranks = []
    diagnostics = []

    for item in queries:
        query = item["query"]
        expected = set(item["expected_categories"])
        _expected_sections = set(item.get("expected_sections", []))

        results = retrieval_fn(query, top_k)
        rank_hits = [
            rank
            for rank, result in enumerate(results, start=1)
            if _is_relevant_category(result, expected)
        ]

        hit_at_3 = any(rank <= 3 for rank in rank_hits)
        hit_at_5 = bool(rank_hits)
        first_hit_rank = rank_hits[0] if rank_hits else 0

        recall_at_3_hits += 1 if hit_at_3 else 0
        recall_at_5_hits += 1 if hit_at_5 else 0
        reciprocal_ranks.append(
            1.0 / first_hit_rank if 0 < first_hit_rank <= MRR_MAX_RANK else 0.0
        )

        diagnostics.append({
            "id": item["id"],
            "query": query,
            "expected": sorted(expected),
            "first_hit_rank": first_hit_rank,
            "hit_at_3": hit_at_3,
            "hit_at_5": hit_at_5,
            "retrieved": [
                {"rank": rank, "category": r["category"], "section": r["section"]}
                for rank, r in enumerate(results[:top_k], start=1)
            ],
        })

    total = len(queries)
    return {
        "queries": total,
        "recall_at_3": recall_at_3_hits / total,
        "recall_at_5": recall_at_5_hits / total,
        "mrr": sum(reciprocal_ranks) / total,
        "diagnostics": diagnostics,
    }


def run_evaluation(top_k=TOP_K, hybrid=None, bm25=None, vector=None):
    """Evaluate bm25 / vector / hybrid over the dataset with the real
    retrievers. Accepts injected retriever instances for test reuse.
    """
    if bm25 is None:
        bm25 = BM25Retriever()
    if vector is None:
        vector = VectorRetriever()
    if hybrid is None:
        hybrid = HybridRetriever(bm25=bm25, vector=vector)

    queries = load_dataset()
    modes = {
        "bm25": lambda q, k: bm25.retrieve(q, top_k=k),
        "vector": lambda q, k: vector.retrieve(q, top_k=k),
        "hybrid": lambda q, k: hybrid.retrieve(q, top_k=k),
    }

    report = {}
    for mode, fn in modes.items():
        report[mode] = evaluate_queries(queries, fn, top_k=top_k)
    return report


def print_report(report):
    print("=== RETRIEVAL EVALUATION ===")
    print(f"queries: {next(iter(report.values()))['queries']}, top_k: {TOP_K}")
    print()
    print(f"{'mode':8s} {'Recall@3':>10s} {'Recall@5':>10s} {'MRR':>8s}")
    for mode, result in report.items():
        print(
            f"{mode:8s} "
            f"{result['recall_at_3'] * 100:9.1f}% "
            f"{result['recall_at_5'] * 100:9.1f}% "
            f"{result['mrr'] * 100:7.1f}%"
        )
    print()

    print("=== PER-MODE FAILURE DETAILS ===")
    for mode, result in report.items():
        print(f"\n[{mode}]")
        for diag in result["diagnostics"]:
            if not diag["hit_at_5"]:
                print(f"  miss  {diag['id']}: {diag['query']!r} expected {diag['expected']}")
            elif diag["first_hit_rank"] > 1:
                print(
                    f"  late  {diag['id']}: first hit at rank {diag['first_hit_rank']}"
                    f" (expected {diag['expected']})"
                )


if __name__ == "__main__":
    print_report(run_evaluation())
