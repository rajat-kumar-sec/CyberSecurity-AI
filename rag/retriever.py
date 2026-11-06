"""Hybrid knowledge retrieval for CyberGuard AI (Step 3).

Three retrievers over the same knowledge-chunk records (produced by
rag.chunker and persisted by rag.store):

  - BM25Retriever    keyword matching over the KB corpus (rank-bm25)
  - VectorRetriever  semantic matching via FastEmbed embeddings stored in
                     the existing persistent Chroma collection (Steps 1-2
                     model reused — no second embedding model is loaded)
  - HybridRetriever  Reciprocal Rank Fusion of the two, configurable

All retrievers return the same structured results so they can be swapped
or fused interchangeably:

    {id, title, source_file, category, section, snippet, score,
     retrieval_sources}

Safety: heavy dependencies are imported lazily; empty queries, missing
documents and unavailable/empty vector stores degrade to empty results
instead of exceptions.
"""

from pathlib import Path

from rag.chunker import chunk_knowledge_dir
from rag.store import COLLECTION_NAME, DEFAULT_STORE_PATH, count, get_client


def tokenize(text):
    """Lowercase tokenizer splitting on non-alphanumeric characters.

    Deliberately simple: keeps BM25 explainable and dependency-free.
    """
    token = []
    tokens = []
    for char in text.lower():
        if char.isalnum():
            token.append(char)
        elif token:
            tokens.append("".join(token))
            token = []
    if token:
        tokens.append("".join(token))
    return tokens


def make_snippet(text, max_chars=200):
    """First max_chars of whitespace-normalized chunk text."""
    flat = " ".join(str(text).split())
    if len(flat) <= max_chars:
        return flat
    return flat[:max_chars - 3].rstrip() + "..."


class BM25Retriever:
    """Keyword retriever (BM25Okapi) over the knowledge-base chunks."""

    def __init__(self, chunks=None):
        self.chunks = list(chunks) if chunks is not None else chunk_knowledge_dir()
        self._index = None
        self._ids = []
        if self.chunks:
            self._build()

    def _build(self):
        try:
            from rank_bm25 import BM25Okapi
        except ImportError as exc:
            raise RuntimeError(
                "BM25 retrieval requires the optional 'rank-bm25' package. "
                "Install with: pip install -r rag/requirements.txt"
            ) from exc

        self._index = BM25Okapi([tokenize(c["text"]) for c in self.chunks])
        self._ids = [c["id"] for c in self.chunks]

    def retrieve(self, query, top_k=5):
        """Return structured BM25 results for query (empty query -> [])."""
        if not query or not query.strip() or self._index is None:
            return []

        try:
            scores = self._index.get_scores(tokenize(query))
        except ZeroDivisionError:
            # rank-bm25 raises only on an empty/none-tokenized corpus.
            return []

        ranked = sorted(
            zip(self._ids, scores),
            key=lambda pair: pair[1],
            reverse=True,
        )[:top_k]

        by_id = {c["id"]: c for c in self.chunks}
        results = []
        for rank, (chunk_id, score) in enumerate(ranked, start=1):
            chunk = by_id[chunk_id]
            results.append(self._make_result(chunk, score, rank))

        return results

    def _make_result(self, chunk, score, rank):
        return {
            "id": chunk["id"],
            **{key: chunk["metadata"][key] for key in
               ("title", "source_file", "category", "section")},
            "snippet": make_snippet(chunk["text"]),
            "score": round(float(score), 4),
            "retrieval_sources": ["bm25"],
            "_rank": rank,
        }


class VectorRetriever:
    """Semantic retriever over the persistent Chroma collection.

    Reuses rag.embedder (FastEmbed all-MiniLM-L6-v2, Steps 1-2) — no
    additional embedding model is loaded.
    """

    def __init__(self, store_path=None):
        self.store_path = Path(store_path) if store_path else DEFAULT_STORE_PATH

    def is_available(self):
        """True when the store directory exists and holds documents."""
        if not self.store_path.exists():
            return False
        try:
            return count(store_path=self.store_path) > 0
        except Exception:
            return False

    def retrieve(self, query, top_k=5):
        """Return structured vector-similarity results for query.

        Returns [] when the store is missing/empty or the query is empty;
        never raises on an unavailable store.
        """
        if not query or not query.strip():
            return []

        if not self.is_available():
            return []

        from rag.embedder import embed_texts

        vector = embed_texts([query])[0]

        collection = get_client(self.store_path).get_collection(COLLECTION_NAME)
        raw = collection.query(
            query_embeddings=[list(map(float, vector))],
            n_results=min(top_k, collection.count()),
            include=["documents", "metadatas", "distances"],
        )

        assert len(raw["ids"][0]) == len(raw["documents"][0]), (
            "chroma result fields are misaligned"
        )

        results = []
        for rank, (chunk_id, doc, meta, distance) in enumerate(
            zip(
                raw["ids"][0],
                raw["documents"][0],
                raw["metadatas"][0],
                raw["distances"][0],
            ),
            start=1,
        ):
            # chroma cosine space: distance == 1 - cosine similarity
            similarity = max(0.0, min(1.0, 1.0 - float(distance)))
            results.append({
                "id": chunk_id,
                "title": meta["title"],
                "source_file": meta["source_file"],
                "category": meta["category"],
                "section": meta["section"],
                "snippet": make_snippet(doc),
                "score": round(similarity, 4),
                "retrieval_sources": ["vector"],
                "_rank": rank,
            })

        return results


class HybridRetriever:
    """RRF-fused retrieval over BM25 + vector rankings.

    score(d) = sum over retrievers r:  weight_r / (rrf_k + rank_r(d))

    RRF is used because BM25 and cosine-similarity scores live on
    incomparable scales; ranks are the only shared currency.
    """

    def __init__(self, bm25=None, vector=None, rrf_k=60,
                 bm25_weight=1.0, vector_weight=1.0, candidates_per_retriever=10):
        self.bm25 = bm25 if bm25 is not None else BM25Retriever()
        self.vector = vector if vector is not None else VectorRetriever()
        self.rrf_k = rrf_k
        self.bm25_weight = bm25_weight
        self.vector_weight = vector_weight
        self.candidates_per_retriever = candidates_per_retriever

    def retrieve(self, query, top_k=5):
        if not query or not query.strip():
            return []

        n = max(top_k, self.candidates_per_retriever)
        bm25_hits = self.bm25.retrieve(query, top_k=n)
        vector_hits = self.vector.retrieve(query, top_k=n)

        contributions = {}   # id -> {weight_sum, result fields}
        sources = {}         # id -> set of source tags

        for hits, weight in ((bm25_hits, self.bm25_weight),
                             (vector_hits, self.vector_weight)):
            # De-duplicate within one ranking, then accumulate RRF mass.
            seen_in_ranking = set()
            for hit in hits:
                if hit["id"] in seen_in_ranking:
                    continue
                seen_in_ranking.add(hit["id"])

                if hit["id"] not in contributions:
                    contributions[hit["id"]] = {
                        "weight_sum": 0.0,
                        "result": {key: hit[key] for key in
                                   ("id", "title", "source_file", "category",
                                    "section", "snippet")},
                    }
                contributions[hit["id"]]["weight_sum"] += weight / (self.rrf_k + hit["_rank"])
                sources.setdefault(hit["id"], set()).update(hit["retrieval_sources"])

        fused = sorted(
            contributions.items(),
            key=lambda item: item[1]["weight_sum"],
            reverse=True,
        )[:top_k]

        results = []
        for rank, (chunk_id, payload) in enumerate(fused, start=1):
            result = dict(payload["result"])
            # Full-precision RRF sum — rounding would hide fuse-order effects.
            result["score"] = float(payload["weight_sum"])
            result["retrieval_sources"] = sorted(sources[chunk_id])
            result["_rank"] = rank
            results.append(result)

        return results


def retrieve(query, top_k=5, mode="hybrid", **kwargs):
    """Convenience dispatcher used by tests and (later) app integration."""
    retrievers = {
        "bm25": BM25Retriever,
        "vector": VectorRetriever,
        "hybrid": HybridRetriever,
    }
    if mode not in retrievers:
        raise ValueError(f"unknown retrieval mode: {mode!r}")
    return retrievers[mode](**kwargs).retrieve(query, top_k=top_k)
