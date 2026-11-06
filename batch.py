"""Batch log-file analysis (roadmap item 4).

Analyses a whole text log file, one line at a time, with the same rule engine
used for a single log. Nothing here re-implements the detection rules: every
line is passed to :func:`analyzer.analyze_log`, so a line's verdict is identical
whether it was submitted through the single-log form or as part of a file.

Design notes
------------
* Only the standard library plus the existing analyzer are used.
* Identical lines are analysed once and mapped back to every line number, which
  keeps repetitive logs (a common shape for auth logs) cheap.
* The line count is capped so one request cannot pin the CPU: the analyzer runs
  a scikit-learn prediction per line, measured at roughly 20-40 ms per line on
  the reference laptop. The cap is configurable with
  ``CYBERGUARD_BATCH_MAX_LINES`` and hard-limited to :data:`HARD_MAX_LINES`.
* Every line that fails to analyse is counted, never silently dropped, and the
  endpoint reports a partial result rather than a 500.

This module never writes files and never sends anything over the network.
"""

import io
import os
import time
from collections import Counter

from analyzer import analyze_log

MAX_UPLOAD_BYTES = 1024 * 1024
DEFAULT_MAX_LINES = 200
HARD_MAX_LINES = 2000
MAX_LINE_CHARS = 2000
DEFAULT_MAX_SAMPLES = 50
MAX_SAMPLES = 200

MAX_LINES_ENV = "CYBERGUARD_BATCH_MAX_LINES"

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def max_lines():
    """Resolve the per-request line cap from the environment.

    Invalid or out-of-range values fall back to the default: a bad environment
    variable must never disable the cap.
    """
    raw = os.environ.get(MAX_LINES_ENV)

    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MAX_LINES

    if value < 1:
        return DEFAULT_MAX_LINES

    return min(value, HARD_MAX_LINES)


def decode_text(payload):
    """Decode uploaded bytes as UTF-8 (with BOM) and fall back to Latin-1.

    Latin-1 cannot fail, so any byte sequence produces text instead of raising.
    """
    if isinstance(payload, str):
        return payload

    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be str or bytes")

    try:
        return bytes(payload).decode("utf-8-sig")
    except UnicodeDecodeError:
        return bytes(payload).decode("latin-1")


def parse_lines(text, limit=None):
    """Split log text into analysable lines.

    Returns a dict with the (capped) ``lines``, how many non-blank lines the
    file held, and counters for blank, over-long and dropped lines.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    limit = max_lines() if limit is None else limit

    normalised = text.replace("\r\n", "\n").replace("\r", "\n")

    lines = []
    total = 0
    blank = 0
    clipped = 0

    for raw in normalised.split("\n"):
        candidate = raw.strip()

        if not candidate:
            blank += 1
            continue

        total += 1

        if len(lines) >= limit:
            continue

        if len(candidate) > MAX_LINE_CHARS:
            candidate = candidate[:MAX_LINE_CHARS]
            clipped += 1

        lines.append(candidate)

    return {
        "lines": lines,
        "lines_total": total,
        "blank_lines": blank,
        "clipped_lines": clipped,
        "truncated": total > len(lines),
        "limit": limit,
    }


def _snippet(text, limit=160):
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def _sort_counts(counter, order=None):
    if order:
        return sorted(
            counter.items(),
            key=lambda item: (order.get(item[0], 99), -item[1], item[0]),
        )
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))


def analyze_text(text, filename=None, limit=None, max_samples=DEFAULT_MAX_SAMPLES,
                 analyze=analyze_log):
    """Analyse every line of ``text`` and summarise the results.

    ``analyze`` is injectable so tests can run without the ML model.
    """
    started = time.perf_counter()

    parsed = parse_lines(text, limit=limit)
    lines = parsed["lines"]

    if max_samples is None:
        max_samples = DEFAULT_MAX_SAMPLES
    max_samples = max(1, min(int(max_samples), MAX_SAMPLES))

    # One analysis per distinct line; identical lines share the result.
    unique_lines = list(dict.fromkeys(lines))

    results = {}
    errors = []

    for line in unique_lines:
        try:
            results[line] = analyze(line)
        except Exception as exc:  # noqa: BLE001 - one bad line must not fail the file
            errors.append({
                "line": _snippet(line, 120),
                "error": f"{type(exc).__name__}: {exc}",
            })

    threat_counts = Counter()
    risk_counts = Counter()
    samples = []
    suspicious = 0
    skipped_lines = 0

    for index, line in enumerate(lines, start=1):
        result = results.get(line)

        if result is None:
            skipped_lines += 1
            continue

        threat = result.get("threat_type") or "Unknown"
        risk = result.get("risk") or "UNKNOWN"

        threat_counts[threat] += 1
        risk_counts[risk] += 1

        if threat == "Unknown":
            continue

        suspicious += 1

        if len(samples) < max_samples:
            samples.append({
                "line_number": index,
                "threat_type": threat,
                "risk": risk,
                "ml_prediction": result.get("ml_prediction"),
                "ml_confidence": result.get("ml_confidence"),
                "username": result.get("username"),
                "source_ip": result.get("source_ip"),
                "attempts": result.get("attempts"),
                "snippet": _snippet(line),
            })

    analysed = len(lines) - skipped_lines

    return {
        "available": True,
        "filename": filename or None,
        "lines_total": parsed["lines_total"],
        "lines_analyzed": analysed,
        "blank_lines": parsed["blank_lines"],
        "clipped_lines": parsed["clipped_lines"],
        "unique_lines": len(unique_lines),
        "duplicates_collapsed": len(lines) - len(unique_lines),
        "truncated": parsed["truncated"],
        "limit": parsed["limit"],
        "max_samples": max_samples,
        "suspicious": suspicious,
        "benign": analysed - suspicious,
        "threat_types": [
            {"threat_type": name, "count": count}
            for name, count in _sort_counts(threat_counts)
        ],
        "risks": [
            {"risk": name, "count": count}
            for name, count in _sort_counts(risk_counts, RISK_ORDER)
        ],
        "samples": samples,
        "samples_truncated": suspicious > len(samples),
        "errors": errors[:10],
        "error_count": len(errors),
        "skipped_lines": skipped_lines,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "error": None,
    }


def analyze_bytes(payload, filename=None, limit=None, analyze=analyze_log):
    """Decode uploaded bytes and analyse them."""
    return analyze_text(
        decode_text(payload), filename=filename, limit=limit, analyze=analyze
    )


def main(argv=None):
    """CLI: ``python batch.py <file> [--limit N] [--json]``."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="Analyse a log file line by line (no network, no LLM)."
    )
    parser.add_argument("path", help="path to a .log/.txt file")
    parser.add_argument("--limit", type=int, default=None,
                        help=f"max lines to analyse (default {DEFAULT_MAX_LINES})")
    parser.add_argument("--json", action="store_true",
                        help="print the full JSON report")
    args = parser.parse_args(argv)

    with io.open(args.path, "rb") as handle:
        payload = handle.read()

    if len(payload) > MAX_UPLOAD_BYTES:
        print(
            f"File is {len(payload)} bytes; the limit is {MAX_UPLOAD_BYTES}.",
            file=sys.stderr,
        )
        return 2

    report = analyze_bytes(
        payload, filename=os.path.basename(args.path), limit=args.limit
    )

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"File: {report['filename']}")
    print(
        f"Lines analysed: {report['lines_analyzed']} of "
        f"{report['lines_total']} ({report['blank_lines']} blank)"
    )
    if report["truncated"]:
        print(f"Truncated at {report['limit']} lines.")
    print(f"Suspicious: {report['suspicious']} | Benign: {report['benign']}")
    print(f"Duration: {report['duration_ms']} ms")
    print()
    print("Threat types:")
    for row in report["threat_types"]:
        print(f"  {row['threat_type']}: {row['count']}")
    print()
    print("Risk levels:")
    for row in report["risks"]:
        print(f"  {row['risk']}: {row['count']}")

    if report["errors"]:
        print()
        print("Lines that failed to analyse:")
        for row in report["errors"]:
            print(f"  {row['error']}: {row['line']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
