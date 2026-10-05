# CryptoHarness Core + Docker — Design Spec (2026-10-05)

Approved by user on 2026-10-05. Scope: Core + Docker first (PRD §M0–M4 subset).

## 1. Goal
Streaming spectral anomaly detection CLI (`cryptoh`) + Dockerfile, 100% free stack,
no paid credits. Dashboard (M5) and deploy/calibration (M6) deferred.

## 2. Architecture
`cryptoh` CLI (typer + rich + pyfiglet banner) with `watch / batch / list / --version`.
Pipeline: ingest (tumbling 5s window) → graph build (A, D, L_norm) →
3 spectral detectors → 2-of-3 rule → k-node subgraph extract →
DOT + PNG render → Gemma diagnose (live if GEMINI_API_KEY, else heuristic
fallback) → validated mitigation → operator y/N → NDJSON audit log.

## 3. Components
- `cryptoh/spectral/`: `laplacian.py` (normalized L via scipy.sparse),
  `fiedler.py` (λ₂ drop, δ=0.20), `multiplicity.py` (zero-mult, ε=0.01),
  `clustering.py` (spectral embedding outlier, μ+3σ), `rule.py` (2-of-3),
  `baseline.py` (first-60s baseline, no alerts before established).
- `cryptoh/ingest/`: `window.py`, `graph_builder.py`,
  `sources/base.py` Protocol + `nginx_access_log.py`, `csv_file.py`,
  `json_stream.py`, `_template.py`. (pcap/docker/ebpf/vpc/syslog deferred.)
- `cryptoh/extract/`: `subgraph.py` (k=8 default), `dot_render.py`, `png_render.py`
  (matplotlib dark theme, red anomalies).
- `cryptoh/llm/`: `gemma.py` (google-genai, model gemma-3-27b-it via Gemini API),
  `fallback.py` (deterministic heuristic diagnosis, no key needed),
  `prompts/diagnose.py`, `parser.py` (JSON parse + 2 retries then text fallback).
- `cryptoh/mitigate/`: `iptables.py`, `docker_policy.py`, `k8s_networkpolicy.py`,
  `nginx_config.py` validators + `templates/*.j2`. Never auto-applied.
- `cryptoh/tui/`: `operator.py` (colored diag), `confirm.py`, `audit.py`.
- `cryptoh/core/`: `events.py` (pydantic), `trace.py` (NDJSON recorder), `config.py`.
- `cryptoh/cli.py`, `banner.py`, `__main__.py`, `__init__.py`.

## 4. Data flow
log line → (src, dst, weight) edge → A/D/L_norm → λ₂, multiplicity, outliers →
anomaly event → PNG + DOT + filtered logs → diagnosis JSON → mitigation + y/N.

## 5. Error handling
No alerts before 60s baseline; bad Gemini JSON → 2 retries → text fallback;
unvalidatable mitigation → ⚠ UNVALIDATED display; PII scrub before any LLM call;
`--no-mitigate` detection-only mode to protect free-tier RPM during demo.

## 6. Testing
pytest per module (laplacian/fiedler/multiplicity/clustering/rule/sources/
extract/gemma/mitigate/cli) + ruff. All tests run with no API key (mocked LLM).

## 7. Packaging / Docker / repo
- `pyproject.toml` (requires-python>=3.11, console_script `cryptoh`), `uv.lock`,
  `.python-version` 3.12 (system toolchain; PRD said 3.11, user chose 3.12+uv).
- `Dockerfile`: python:3.12-slim + uv, `uv sync --frozen`, serves FastAPI
  (serve stub now, full server in M5); `render.yaml`, `.env.example`.
- Fix `.gitignore` (stop ignoring README.md, Roadmap/), restore README.md.
- `data/nginx_normal.log`, `data/nginx_c2_attack.log` + `scripts/replay-attack.sh`.

## 8. Non-goals (this phase)
FastAPI dashboard + animations (M5), Render/HF deploy (M6), CIC-IDS2017
calibration, STIX export, Ollama local backend, pcap/docker/ebpf/vpc sources.

## Spec self-review
No TBDs; sections consistent (serve ships as stub noting M5); scope is one
implementation plan; thresholds explicit (δ, ε, μ+3σ, 2-of-3, 60s, k=8).
