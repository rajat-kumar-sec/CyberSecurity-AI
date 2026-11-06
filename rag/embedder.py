"""Embedding wrapper around FastEmbed (ONNX MiniLM).

Typed-use model: sentence-transformers/all-MiniLM-L6-v2 (384-dim, Apache-2.0).
FastEmbed runs an ONNX export converted from the sentence-transformers model;
the embedding space/dimension match, but vectors are not guaranteed to be
bit-identical to a torch sentence-transformers run.

The heavyweight dependency is imported lazily so that loading the Flask app
or running the analyzer never fails when RAG dependencies aren't installed.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIM = 384

# model_cache kept inside the project (git-ignored) so downloads are
# explicit and predictable. First run requires internet once.
MODEL_CACHE_DIR = BASE_DIR / "data" / "model_cache"

_embedder = None


def get_embedder():
    """Return a lazily-initialized FastEmbed TextEmbedding singleton.

    Raises a descriptive RuntimeError if fastembed is not installed, so
    callers can degrade gracefully instead of crashing the application.
    """
    global _embedder
    if _embedder is None:
        try:
            from fastembed import TextEmbedding
        except ImportError as exc:
            raise RuntimeError(
                "RAG embedding requires the optional 'fastembed' package. "
                "Install with: pip install -r rag/requirements.txt — "
                "or run without RAG features."
            ) from exc

        _embedder = TextEmbedding(
            model_name=MODEL_NAME,
            cache_dir=str(MODEL_CACHE_DIR),
        )
    return _embedder


def embed_texts(texts):
    """Embed a list of texts, returning a list of 384-dim float vectors.

    Validates dimensionality on every call and returns deterministic
    batched results (input order preserved).
    """
    if not texts:
        return []

    vectors = list(get_embedder().embed(list(texts)))

    # FastEmbed yields NumPy arrays; normalize to plain float lists so
    # values are storable/serializable and equality comparisons are exact.
    vectors = [list(map(float, vector)) for vector in vectors]

    for vector in vectors:
        if len(vector) != EMBEDDING_DIM:
            raise RuntimeError(
                f"Embedding dimension mismatch: expected {EMBEDDING_DIM}, "
                f"got {len(vector)}"
            )

    return vectors
