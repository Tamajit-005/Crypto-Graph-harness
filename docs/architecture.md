# Crypto-Graph Harness Architecture

Five-stage pipeline: ingest → build graph → spectral analyze → extract subgraph → diagnose and mitigate.

- `cryptoh/ingest/` — telemetry source adapters and tumbling window graph builder.
- `cryptoh/spectral/` — normalized Laplacian, three spectral anomaly signals, 2-of-3 rule, rolling baseline.
- `cryptoh/extract/` — k-node anomaly subgraph extraction, DOT and PNG rendering.
- `cryptoh/llm/` — Gemma 4 via Gemini API, prompt templates, response parser, PII scrubber.
- `cryptoh/mitigate/` — iptables, Docker, k8s, nginx validators and Jinja2 templates.
- `cryptoh/tui/` — colored operator diagnosis, y/N apply prompt, NDJSON audit log.
- `cryptoh/web/` — FastAPI server, SSE stream, static dashboard.
- `cryptoh/core/` — shared analysis pipeline and Pydantic event types.

The spectral layer is source-agnostic; source-specific logic lives in `cryptoh/ingest/sources/`.
