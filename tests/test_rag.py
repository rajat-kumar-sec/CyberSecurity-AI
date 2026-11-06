"""Tests for the RAG module skeleton (Steps 1-2).

Chunker, metadata and ID tests run with stdlib only.
Embedding and persistence tests skip automatically when the optional
RAG dependencies (fastembed / chromadb) are not installed, guaranteeing
the core test suite never depends on RAG packages.
"""

import pytest

pytest.importorskip("fastembed", reason="RAG deps not installed")
pytest.importorskip("chromadb", reason="RAG deps not installed")

from rag.embedder import EMBEDDING_DIM, MODEL_NAME, embed_texts
from rag.chunker import (
    CATEGORY_BY_FILE,
    chunk_file,
    chunk_knowledge_dir,
    chunk_text,
    make_chunk_id,
    parse_title,
)
from rag.store import (
    COLLECTION_NAME,
    count,
    get_all_ids,
    get_client,
    replace_collection,
)


# ---------------------------------------------------------------- chunking

KB_TXT = """Threat: Test Threat

Description:
A test threat used for unit testing.

Common Indicators:
- One indicator
- Another indicator

Risk:
Moderate risk of tests failing unexpectedly.
"""


def test_chunk_text_sections():
    sections = chunk_text(KB_TXT)

    names = [name for name, _ in sections]
    assert names == ["Description", "Common Indicators", "Risk"]
    assert "A test threat used for unit testing." in dict(sections)["Description"]


def test_chunk_text_keeps_placeholder_tolerant():
    """Extra/unknown sections must not be rejected."""
    sections = chunk_text("Threat: X\n\nExtra Section:\ncontent\n")

    assert [name for name, _ in sections] == ["Extra Section"]


def test_parse_title():
    assert parse_title(KB_TXT) == "Test Threat"
    assert parse_title("no title here") is None


def test_chunk_file_metadata(tmp_path):
    kb = tmp_path / "kb.txt"
    kb.write_text(KB_TXT, encoding="utf-8")

    chunks = chunk_file(kb, knowledge_dir=tmp_path)

    assert len(chunks) == 3
    for chunk in chunks:
        assert set(chunk["metadata"]) == {"title", "source_file", "category", "section"}
        assert chunk["metadata"]["title"] == "Test Threat"
        assert chunk["metadata"]["source_file"] == "kb.txt"
        assert chunk["metadata"]["category"] == "Kb"  # stem fallback ("kb.txt" -> "Kb")


def test_chunk_file_uses_canonical_category():
    path = "data/knowledge/brute_force.txt"
    chunks = chunk_file(path)

    assert {chunk["metadata"]["category"] for chunk in chunks} == {
        CATEGORY_BY_FILE["brute_force.txt"]
    }
    assert all(chunk["metadata"]["source_file"] == "brute_force.txt" for chunk in chunks)


def test_chunk_knowledge_dir_covers_all_files(tmp_path):
    for name in ("a.txt", "b.txt"):
        (tmp_path / name).write_text(KB_TXT, encoding="utf-8")

    chunks = chunk_knowledge_dir(tmp_path)

    assert len(chunks) == 6  # 3 sections x 2 files


# ---------------------------------------------------------- deterministic ids

def test_chunk_ids_deterministic(tmp_path):
    kb = tmp_path / "kb.txt"
    kb.write_text(KB_TXT, encoding="utf-8")

    first = chunk_file(kb)
    second = chunk_file(kb)
    assert first == second


def test_chunk_id_changes_when_content_changes():
    id_a = make_chunk_id("Brute Force", "Description", "Original content.")
    id_b = make_chunk_id("Brute Force", "Description", "Changed content.")

    assert id_a != id_b


def test_chunk_id_stable_for_equivalent_whitespace():
    id_a = make_chunk_id("Brute Force", "Description", "Same   content\nwith gaps")
    id_b = make_chunk_id("Brute Force", "Description", "Same content with gaps")

    assert id_a == id_b


def test_chunk_id_changes_with_section_or_category():
    content = "Shared content"
    base = make_chunk_id("Brute Force", "Description", content)

    assert base != make_chunk_id("Brute Force", "Risk", content)
    assert base != make_chunk_id("Malware", "Description", content)


# ------------------------------------------------------------------ embedder

def test_embed_text_dimension_and_normalization():
    vectors = embed_texts(["Failed password for root", "normal backup finished"])

    assert len(vectors) == 2
    for vector in vectors:
        assert len(vector) == EMBEDDING_DIM == 384
        norm = sum(value * value for value in vector) ** 0.5
        assert norm == pytest.approx(1.0, abs=1e-5)


def test_embed_texts_deterministic_and_order_preserving():
    texts = ["brute force attack blocked", "sql injection union select"]
    first = embed_texts(texts)
    second = embed_texts(texts)

    assert len(first) == 2 == len(second)
    assert first[0] == second[0]
    assert first[0] != first[1]


def test_embed_empty_list_is_noop():
    assert embed_texts([]) == []


def test_embedder_model_identity():
    """Guard the exact model under test had been intended (384-d MiniLM)."""
    assert MODEL_NAME == "sentence-transformers/all-MiniLM-L6-v2"
    assert EMBEDDING_DIM == 384


# -------------------------------------------------------------------- store

def _fake_records(n):
    return [
        {
            "id": f"id-{i}",
            "text": f"document {i}",
            "metadata": {"title": f"Doc {i}", "source_file": "x.txt",
                          "category": "C", "section": "Description"},
        }
        for i in range(n)
    ]


def test_replace_collection_and_query_roundtrip(tmp_path):
    """Uses synthetic 2-dim vectors: no embedding model required."""
    store_path = tmp_path / "vs"
    vectors = [[1.0, 0.0], [0.0, 1.0], [0.5, 0.5]]
    records = _fake_records(3)

    replace_collection(records, vectors, store_path=store_path)
    assert count(store_path=store_path) == 3

    collection = get_client(store_path).get_collection(COLLECTION_NAME)
    assert collection.get()["ids"] == ["id-0", "id-1", "id-2"]


def test_store_records_metadata_fields(tmp_path):
    store_path = tmp_path / "vs"

    records = _fake_records(1)
    vectors = [[1.0, 0.0]]
    replace_collection(records, vectors, store_path=store_path)

    collection = get_client(store_path).get_collection(COLLECTION_NAME)
    entry = collection.get(ids=["id-0"], include=["metadatas", "documents"])
    assert entry["metadatas"][0]["source_file"] == "x.txt"
    assert entry["documents"][0] == "document 0"


def test_store_counts_after_replace(tmp_path):
    store_path = tmp_path / "vs"

    replace_collection(_fake_records(4), [[i, 1.0] for i in range(4)], store_path=store_path)
    assert count(store_path=store_path) == 4

    # Replacing shrinks the collection instead of appending duplicates.
    replace_collection(_fake_records(2), [[1.0, 0.0], [0.0, 1.0]], store_path=store_path)
    assert count(store_path=store_path) == 2


# ---------------------------------------------------------------- ingestion

KB_A = "Threat: Ingest Alpha\n\nDescription:\nalpha description.\n"
KB_B = "Threat: Ingest Beta\n\nDescription:\nbeta description.\n"


def _setup_kb(tmp_path):
    kb = tmp_path / "kb"
    kb.mkdir()
    (kb / "alpha.txt").write_text(KB_A, encoding="utf-8")
    (kb / "beta.txt").write_text(KB_B, encoding="utf-8")
    return kb


def _new_ingest(kb_dir, store_path):
    from ingest_knowledge import ingest
    return ingest(knowledge_dir=kb_dir, store_path=store_path)


def test_ingestion_persists_expected_chunks(tmp_path):
    kb = _setup_kb(tmp_path)
    store_path = tmp_path / "vs"

    summary = _new_ingest(kb, store_path)

    assert summary["chunks"] == 2
    assert summary["count_after"] == count(store_path=store_path)


def test_repeated_ingestion_creates_no_duplicates(tmp_path):
    kb = _setup_kb(tmp_path)
    store_path = tmp_path / "vs"

    _new_ingest(kb, store_path)
    count_first = count(store_path=store_path)
    _new_ingest(kb, store_path)
    count_second = count(store_path=store_path)

    assert count_first == count_second == 2
    ids = get_all_ids(store_path=store_path)
    assert len(ids) == len(set(ids)) == 2


def test_content_change_leaves_no_stale_chunks(tmp_path):
    kb = _setup_kb(tmp_path)
    store_path = tmp_path / "vs"

    _new_ingest(kb, store_path)
    ids_before = set(get_all_ids(store_path=store_path))

    (kb / "alpha.txt").write_text(
        "Threat: Ingest Alpha\n\nDescription:\nREVISED description.\n",
        encoding="utf-8",
    )
    _new_ingest(kb, store_path)

    ids_after = set(get_all_ids(store_path=store_path))
    assert len(ids_after) == 2
    assert len(ids_after & ids_before) == 1  # alpha id changed, beta's kept
