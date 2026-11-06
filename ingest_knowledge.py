"""Ingest the knowledge base (Steps 1-2 of the RAG plan).

Reads data/knowledge/*.txt, chunks section-by-section, embeds with
FastEmbed MiniLM (first run downloads the ~0.09 GB model once), and fully
rebuilds the persistent Chroma collection under data/vectorstore/.

Idempotent by construction: every ingest is a full rebuild, so repeated
runs create no duplicates, and content changes never leave stale chunks.

Usage:
    python ingest_knowledge.py                 # ingest with defaults
    python ingest_knowledge.py --store-path <custom_dir>
"""

import argparse

from rag.chunker import DEFAULT_KNOWLEDGE_DIR, chunk_knowledge_dir
from rag.embedder import MODEL_NAME, EMBEDDING_DIM, embed_texts
from rag.store import DEFAULT_STORE_PATH, count


def ingest(knowledge_dir=None, store_path=None):
    """Run one full ingestion and return a summary dict."""
    knowledge_dir = knowledge_dir or DEFAULT_KNOWLEDGE_DIR
    store_path = store_path or DEFAULT_STORE_PATH

    chunks = chunk_knowledge_dir(knowledge_dir)

    if not chunks:
        raise RuntimeError(
            f"No knowledge chunks produced from '{knowledge_dir}' — "
            "nothing ingested."
        )

    vectors = embed_texts([chunk["text"] for chunk in chunks])

    from rag.store import get_client, replace_collection

    client = get_client(store_path)
    before = count(client=client)
    _ = replace_collection(chunks, vectors, store_path=store_path, client=client)
    after = count(client=client)

    per_file = {}
    for chunk in chunks:
        source = chunk["metadata"]["source_file"]
        per_file[source] = per_file.get(source, 0) + 1

    return {
        "knowledge_dir": str(knowledge_dir),
        "store_path": str(store_path),
        "model": MODEL_NAME,
        "embedding_dim": EMBEDDING_DIM,
        "chunks": len(chunks),
        "per_file": per_file,
        "count_before": before,
        "count_after": after,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--knowledge-dir", default=None)
    parser.add_argument("--store-path", default=None)
    args = parser.parse_args()

    summary = ingest(
        knowledge_dir=args.knowledge_dir,
        store_path=args.store_path,
    )

    print("=== KNOWLEDGE INGESTION ===")
    print("Knowledge dir:", summary["knowledge_dir"])
    print("Model:", summary["model"], f"({summary['embedding_dim']} dims)")
    print("Chunks by file:")
    for source, total in sorted(summary["per_file"].items()):
        print(f"  - {source}: {total} chunks")
    print("Total chunks:", summary["chunks"])
    print("Collection count:", summary["count_after"])
    print("Full rebuild (no duplicates, no stale chunks).")
    print("Vector store:", summary["store_path"])


if __name__ == "__main__":
    main()
