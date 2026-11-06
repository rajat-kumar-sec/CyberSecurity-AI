"""Persistent Chroma vector store for the knowledge base.

The dependency is imported lazily so the rest of the application keeps
working when chromadb is not installed.

Store layout:
    data/vectorstore/          <- Chroma persistent directory
    collection: "knowledge"    <- one record per knowledge chunk

Embedding vectors are provided by rag.embedder and are stored directly —
Chroma's built-in default embedding function is never used, so no
internet/model download happens at query time.

Write model: full rebuild (delete + recreate + add). The corpus is small,
and a rebuild guarantees there are never duplicate chunks or obsolete
stale chunks left behind after content changes.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULT_STORE_PATH = BASE_DIR / "data" / "vectorstore"
COLLECTION_NAME = "knowledge"
BATCH_SIZE = 100


def _require_chromadb():
    try:
        import chromadb
    except ImportError as exc:
        raise RuntimeError(
            "RAG persistence requires the optional 'chromadb' package. "
            "Install with: pip install -r rag/requirements.txt — "
            "or run without RAG features."
        ) from exc
    return chromadb


def get_client(store_path=None):
    """Open (creating on demand) a persistent Chroma client at store_path."""
    chromadb = _require_chromadb()
    store_path = Path(store_path) if store_path else DEFAULT_STORE_PATH
    store_path.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(store_path))


def get_collection(client):
    """Get or create the knowledge collection (cosine distance space)."""
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )


def replace_collection(records, vectors, store_path=None, client=None):
    """Atomically replace the whole collection with new records.

    records: list of {id, text, metadata} from rag.chunker
    vectors: list of embedding vectors aligned with records

    Returns the number of documents in the new collection.
    """
    if len(records) != len(vectors):
        raise ValueError(
            f"records/vectors mismatch: {len(records)} records, "
            f"{len(vectors)} vectors"
        )

    if client is None:
        client = get_client(store_path)

    # Drop the old collection entirely: removes any duplicate or stale
    # chunks from previous ingests regardless of what happened before.
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        # Collection does not exist yet on the first ingest — fine to ignore.
        pass

    collection = get_collection(client)

    for start in range(0, len(records), BATCH_SIZE):
        batch = records[start:start + BATCH_SIZE]
        collection.add(
            ids=[record["id"] for record in batch],
            documents=[record["text"] for record in batch],
            embeddings=[list(map(float, vector)) for vector in vectors[start:start + BATCH_SIZE]],
            metadatas=[dict(record["metadata"]) for record in batch],
        )

    return len(records)


def count(store_path=None, client=None):
    """Number of chunks currently in the persisted collection."""
    if client is None:
        client = get_client(store_path)
    collection = get_collection(client)
    return collection.count()


def get_all_ids(store_path=None, client=None):
    """All chunk IDs currently persisted (used to verify idempotence)."""
    if client is None:
        client = get_client(store_path)
    collection = get_collection(client)
    result = collection.get(include=[])
    return sorted(result["ids"])


def query_texts(store_path, query_texts, embedder, n_results=5):
    """Embed query texts and query the store, returning raw Chroma results.

    Query embedding is done by the caller-supplied embedder (fastembed),
    not by Chroma's optional default ONNX embedding function.
    """
    collection = get_collection(get_client(store_path))

    if hasattr(embedder, "__call__") and not isinstance(embedder, (list, tuple)):
        query_vectors = embedder(list(query_texts))
    else:
        query_vectors = embedder(query_texts)

    if len(query_vectors) != len(list(query_texts)):
        raise ValueError("query vector count does not match query text count")

    return collection.query(
        query_embeddings=[list(map(float, vector)) for vector in query_vectors],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )
