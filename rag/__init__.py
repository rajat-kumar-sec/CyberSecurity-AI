"""RAG building blocks for CyberGuard AI.

Implemented:
  Steps 1-2  chunking, FastEmbed embeddings, persistent Chroma store, ingestion
  Step 3     BM25 / vector / RRF hybrid retrieval plus retrieval evaluation
  Step 4     application integration (rag.context): retrieval surfaced in the
             Flask dashboard and API
  Step 5     assistant context supply (rag.assistant): grounded prompt,
             deterministic summary, optional local Ollama adapter

Planned (not implemented): chat UI, user-approved conversation memory.
"""
