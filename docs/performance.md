# Performance and Reliability Measurements

These are **measured** values from a single local run on the project host, not
estimates or synthetic benchmarks. Re-run the probe on your own machine before
quoting them.

## Environment

| Item | Value |
| --- | --- |
| OS | Windows 10 x64 |
| CPU | 4 logical processors |
| RAM | 8 GB class |
| Python | 3.14.8 |
| Model artifact | `models/threat_classifier.joblib` |
| RAG | FastEmbed `all-MiniLM-L6-v2` (ONNX), Chroma persistent store |

## Method

- Cold import timings were measured with three fresh `python -c "import ..."`
  processes and averaged.
- In-process timings used `time.perf_counter()`.
- Memory is the Python process working set reported by
  `GetProcessMemoryInfo` (not total system memory).
- Retrieval was measured after one warm-up call.
- Batch analysis used a synthetic 100-line log (50 unique lines) and the real
  analyzer/ML model.

## Results

### Startup and loading

| Operation | Result |
| --- | --- |
| `import analyzer` (includes joblib model load), fresh process | ~2.70–2.76 s |
| `import app` (includes analyzer), fresh process | ~3.08–3.14 s |
| Flask app import after the analyzer is already loaded | ~0.31 s |
| RAG embedder initialization (model cache present) | ~1.37 s |

The app import is dominated by loading scikit-learn and the joblib model.
Importing the Flask app does **not** initialize the RAG embedder or the vector
store; those load lazily on the first retrieval.

### Retrieval

| Operation | Result |
| --- | --- |
| First hybrid retrieval (builds BM25 + loads vector store) | ~1.28–1.47 s |
| Warm hybrid retrieval (`top_k=4`) | ~20–27 ms (median ~20.5 ms) |
| Passages returned | 4 |
| Retrieval available | yes |

### Batch analysis

| Operation | Result |
| --- | --- |
| 100 lines (100 unique) through the real analyzer | ~1.99 s |
| Per line | ~20 ms |
| Default per-request cap | 200 non-blank lines |
| Hard cap | 2000 non-blank lines |

At the default 200-line cap a maximum-size batch is roughly 4 seconds of CPU on
this host. The hard cap keeps worst-case requests bounded at roughly 40 seconds;
raise `CYBERGUARD_BATCH_MAX_LINES` only deliberately.

### Memory

| Point | Working set |
| --- | --- |
| Process start | ~18 MB |
| After analyzer + ML model load | ~118 MB |
| After Flask app import | ~128 MB |
| After RAG embedder initialization | ~268 MB |
| After first retrieval | ~306 MB |
| After 100-line batch analysis | ~307 MB |

The app is comfortable on an 8 GB laptop. The optional RAG stack roughly
doubles memory versus the analyzer alone.

## Reliability notes

- Importing `app.py` is side-effect free apart from loading the ML model; the
  defense service performs no I/O until an endpoint is called.
- The RAG layer degrades to `available: false` when optional dependencies or
  the vector store are missing; the analysis endpoints keep working.
- Batch analysis caps lines, upload size (1 MiB) and sample count, and reports
  truncation rather than silently dropping input.
- A single-line analysis is bounded by `MAX_LOG_CHARS` (50,000 characters) and
  the global 2 MiB request limit.

## What was not measured

- Browser rendering time on low-end devices.
- Cold-cache RAG initialization with the embedding model absent (requires a
  network download).
- Real UAC/helper latency and firewall command timing (blocked until VM
  validation).
- Long-running multi-user load; this is a local single-user tool.

## Reproducing

The probe used to produce these numbers is intentionally kept outside the
repository so no generated script or local path is committed. To reproduce:

1. Install the runtime and RAG dependencies.
2. Ensure `data/model_cache/` and `data/vectorstore/` exist.
3. Time fresh imports with `Measure-Command`/`time`.
4. Time retrieval and batch calls with `time.perf_counter()`.
5. Read the working set with `GetProcessMemoryInfo` or Task Manager.

Do not commit generated benchmark artifacts or machine-specific paths.
