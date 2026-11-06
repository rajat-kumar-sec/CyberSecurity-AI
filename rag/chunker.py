"""Section-header-aware chunking of the cybersecurity knowledge base.

Splits each data/knowledge/*.txt into one chunk per section
(e.g. "Description:", "Common Indicators:", "Defensive Measures:"),
so each chunk carries its own metadata (title, source_file, category
and section) and a deterministic content-derived ID.

No content is modified here: files are read verbatim. Known inconsistencies
(e.g. unusual wording in network_scanning.txt) are reported separately and
must never be silently fixed by this module.
"""

import hashlib
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_KNOWLEDGE_DIR = BASE_DIR / "data" / "knowledge"

# Canonical threat category per knowledge file, matching the labels used by
# the analyzer/knowledge modules.
CATEGORY_BY_FILE = {
    "brute_force.txt": "Brute Force",
    "malware.txt": "Malware",
    "network_scanning.txt": "Network Scanning",
    "phishing.txt": "Phishing",
    "sql_injection.txt": "SQL Injection",
}

# A section header looks like "Description:" — a short-ish capitalized line
# ending in a colon. Content lines (bullets, sentences, numbered steps) do
# not match.
SECTION_HEADER_RE = re.compile(r"^[A-Z][A-Za-z0-9 ()/',&-]{0,40}:$")

TITLE_LINE_RE = re.compile(r"^Threat:\s*(.+)$")


def _normalize_content(content):
    """Collapse whitespace so equivalent text normalizes identically."""
    return " ".join(content.split())


def make_chunk_id(category, section, content):
    """Deterministic ID from stable identity + verbatim content.

    Changing the content of a section yields a new ID, which guarantees
    that stale chunks with outdated text are never reused.
    """
    digest = hashlib.sha256(
        f"{category}|{section}|{_normalize_content(content)}".encode("utf-8")
    ).hexdigest()
    return f"knowledge-{digest[:24]}"


def parse_title(text):
    """Extract the title from the first non-empty line ('Threat: ...') or None."""
    text = text.strip()
    if not text:
        return None

    match = TITLE_LINE_RE.match(text.splitlines()[0].strip())
    return match.group(1).strip() if match else None


def _split_preamble(body_text):
    """Remove the leading title block so it doesn't leak into section content.

    The preamble counts as a title block only when it is short (the title
    line plus at most a blank line) AND starts with a 'Threat: ...' line.
    Files that don't start with a title keep all their content.
    """
    lines = body_text.strip().splitlines()
    first_header = None
    for index, line in enumerate(lines):
        if SECTION_HEADER_RE.match(line.rstrip()):
            first_header = index
            break

    if first_header is None:
        return lines

    preamble = lines[:first_header]
    preamble_nonempty = [line for line in preamble if line.strip()]
    if len(preamble_nonempty) <= 2 and parse_title("\n".join(preamble)):
        return lines[first_header:]

    return lines


def chunk_text(text):
    """Split raw knowledge-base text into (section, content) pairs.

    Returns a list where each item is a (section_name, content) tuple.
    The title line ("Threat: ...") is excluded from sections; callers get
    the title via parse_title(). Unknown/extra sections are kept — this
    module must tolerate file variations rather than reject them.
    """
    body = _split_preamble(text)
    if not any(line.strip() for line in body):
        return []

    sections = []
    current_section = "Description"
    current_lines = []

    for line in body:
        line = line.rstrip()
        if not line.strip():
            if current_lines:
                current_lines.append(line)
            continue

        if SECTION_HEADER_RE.match(line):
            if current_lines:
                content = "\n".join(current_lines).strip()
                if content:
                    sections.append((current_section, content))
            current_section = line[:-1].strip()
            current_lines = []
        else:
            current_lines.append(line)

    content = "\n".join(current_lines).strip()
    if content:
        sections.append((current_section, content))

    return sections


def chunk_file(path, knowledge_dir=None):
    """Chunk one knowledge file into structured records.

    Each record: {id, text, metadata} where metadata contains
    title, source_file, category and section.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")

    title = parse_title(text) or path.stem
    if knowledge_dir is None:
        source_file = path.name
    else:
        try:
            source_file = path.relative_to(Path(knowledge_dir).resolve()).as_posix()
        except ValueError:
            source_file = path.name
    category = CATEGORY_BY_FILE.get(path.name, path.stem.replace("_", " ").title())

    chunks = []
    for section, content in chunk_text(text):
        chunk_text_full = f"{title} - {section}:\n{content}"
        chunks.append({
            "id": make_chunk_id(category, section, content),
            "text": chunk_text_full,
            "metadata": {
                "title": title,
                "source_file": source_file,
                "category": category,
                "section": section,
            },
        })

    return chunks


def chunk_knowledge_dir(knowledge_dir=None):
    """Chunk every *.txt file in the knowledge directory."""
    knowledge_dir = Path(knowledge_dir) if knowledge_dir else DEFAULT_KNOWLEDGE_DIR

    chunks = []
    for path in sorted(knowledge_dir.glob("*.txt")):
        chunks.extend(chunk_file(path, knowledge_dir=knowledge_dir))

    return chunks
