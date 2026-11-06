"""RAG building blocks for CyberGuard AI.

Implemented:
  Steps 1-2  chunking, FastEmbed embeddings, persistent Chroma store, ingestion
  Step 3     BM25 / vector / RRF hybrid retrieval plus retrieval evaluation
  Step 4     application integration (rag.context): retrieval surfaced in the
             Flask dashboard and API
  Step 5     assistant context supply (rag.assistant): grounded prompt,
             deterministic summary, optional local Ollama adapter
  Step 6     batch log-file analysis (batch.py): per-line verdicts and a
             threat/risk summary, exposed as POST /api/batch and a CLI

The dashboard also has a single-turn chat panel (templates/index.html) on top
of Step 5, with opt-in, browser-owned memory across turns.

Planned (not implemented): carefully controlled defensive actions.
"""
