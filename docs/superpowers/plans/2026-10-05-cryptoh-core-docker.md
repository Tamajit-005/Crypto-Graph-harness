# CryptoHarness Core + Docker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Core + Docker slice of CryptoHarness: `cryptoh` CLI with spectral detection, nginx/csv/json ingest, DOT+PNG extract, Gemma-with-fallback LLM, validated mitigations, tests, sample data, and Dockerfile — all runnable free with no API key.

**Architecture:** Layered package `cryptoh/` (spectral → ingest → extract → llm → mitigate → tui → cli) with pydantic events, NDJSON audit, and a stub FastAPI server exposing `/api/v1/health` so the Docker CMD and Render health check work before M5.

**Tech Stack:** Python ≥3.11 (local 3.12), uv, typer + rich + pyfiglet, numpy + scipy.sparse + networkx, matplotlib (Agg), pydantic + pydantic-settings, google-genai (optional at runtime), jinja2, jsonschema, fastapi + uvicorn, pytest + ruff, Docker (python:3.12-slim + uv).

---
### Task 1: Repo fix + packaging scaffold

**Files:**
- Modify: `.gitignore`
- Create: `pyproject.toml`, `.python-version`, `.env.example`, `cryptoh/__init__.py`, `cryptoh/__main__.py`, `cryptoh/banner.py`, `cryptoh/config.py`
- Test: `tests/conftest.py` (empty marker)

- [ ] **Step 1: Fix `.gitignore`** — replace whole file with:
```
__pycache__/
*.py[cod]
.venv/
uv.lock
*.egg-info/
dist/
build/
.pytest_cache/
.ruff_cache/
cryptoh-report/
cryptoh-audit/
*.png
.env
```
Run: `git show HEAD:README.md > README.md` to restore README (keep its content as-is this phase).
Expected: `git status --short` shows `M .gitignore`, `R README.md` restored.

- [ ] **Step 2: Write `pyproject.toml`** (exact):
```toml
[project]
name = "cryptoh"
version = "0.1.0"
description = "Spectral graph anomaly detection harness with Gemma 4 multimodal diagnostics"
readme = "README.md"
license = { text = "Apache-2.0" }
requires-python = ">=3.11"
dependencies = [
  "typer>=0.9",
  "rich>=13",
  "pyfiglet>=1.0",
  "numpy>=1.26",
  "scipy>=1.11",
  "networkx>=3.2",
  "matplotlib>=3.8",
  "pydantic>=2.5",
  "pydantic-settings>=2.1",
  "google-genai>=1.0",
  "jinja2>=3.1",
  "jsonschema>=4.20",
  "httpx>=0.25",
  "fastapi>=0.109",
  "uvicorn>=0.25",
]

[project.scripts]
cryptoh = "cryptoh.cli:app"

[dependency-groups]
dev = ["pytest>=8", "ruff>=0.2"]

[tool.ruff]
line-length = 100

[tool.pytest.ini_options]
testpaths = ["tests"]
```
`.python-version` content: `3.12`. `.env.example` content: `GEMINI_API_KEY=""\nCRYPTOH_MODEL=gemma-4\n`.

- [ ] **Step 3: Write package scaffold.** `cryptoh/__init__.py`:
```python
"""Crypto-Graph Harness — spectral telemetry diagnostics via Gemma 4."""
__version__ = "0.1.0"

from cryptoh.core.events import AnomalyEvent, SpectralSignals  # noqa: F401
```
`cryptoh/__main__.py`: `from cryptoh.cli import app\n\nif __name__ == "__main__":\n    app()\n`
`cryptoh/banner.py`:
```python
from pyfiglet import figlet_format
from rich.console import Console

SPLASH = figlet_format("CryptoGraph", font="ansi_shadow")
SUBTITLE = "[ Crypto-Graph Harness — Spectral Telemetry Diagnostics via Gemma 4 ]"

def show_banner() -> None:
    Console().print(f"[bright_cyan]{SPLASH}[/bright_cyan][magenta]{SUBTITLE}[/magenta]")
```
`cryptoh/config.py`:
```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    gemini_api_key: str = ""
    model: str = "gemma-4"
    window_seconds: float = 5.0
    baseline_seconds: float = 60.0
    output_dir: str = "cryptoh-report"

    model_config = {"env_prefix": "CRYPTOH_", "extra": "ignore"}

settings = Settings()
```

- [ ] **Step 4: Init env and verify import**
Run: `uv sync --group dev 2>&1 | tail -2 && uv run python -c "import cryptoh; print(cryptoh.__version__)"`
Expected: `0.1.0`

- [ ] **Step 5: Commit**
```bash
git add .gitignore pyproject.toml .python-version .env.example cryptoh README.md
git commit -m "feat: repo fix and packaging scaffold"
```

---
### Task 2: Spectral core (laplacian + 3 detectors + rule + baseline)

**Files:**
- Create: `cryptoh/spectral/__init__.py`, `cryptoh/spectral/laplacian.py`, `cryptoh/spectral/fiedler.py`, `cryptoh/spectral/multiplicity.py`, `cryptoh/spectral/clustering.py`, `cryptoh/spectral/rule.py`, `cryptoh/spectral/baseline.py`
- Test: `tests/test_laplacian.py`, `tests/test_fiedler.py`, `tests/test_multiplicity.py`, `tests/test_clustering.py`, `tests/test_rule.py`

- [ ] **Step 1: Write failing tests** `tests/test_laplacian.py`:
```python
import numpy as np
from scipy import sparse
from cryptoh.spectral.laplacian import normalized_laplacian, smallest_eigenpairs

def test_normalized_laplacian_path_graph():
    A = sparse.csr_matrix(np.array([[0, 1, 0], [1, 0, 1], [0, 1, 0]], dtype=float))
    L = normalized_laplacian(A)
    assert L.shape == (3, 3)
    vals, _ = smallest_eigenpairs(L, k=2)
    assert abs(vals[0]) < 1e-6  # connected graph: λ1 ≈ 0

def test_disconnected_has_two_zeros():
    A = sparse.csr_matrix(np.array([[0, 1, 0, 0], [1, 0, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0]], dtype=float))
    L = normalized_laplacian(A)
    vals, _ = smallest_eigenpairs(L, k=2)
    assert abs(vals[1]) < 1e-6
```
`tests/test_rule.py`:
```python
from cryptoh.spectral.rule import combine

def test_two_of_three_fires():
    assert combine([True, True, False])["anomaly"] is True

def test_single_signal_no_fire():
    assert combine([True, False, False])["anomaly"] is False
```

- [ ] **Step 2: Run to verify they fail**
Run: `uv run pytest tests/test_laplacian.py tests/test_rule.py -v`
Expected: FAIL with "No module named 'cryptoh.spectral'" (or function not defined).

- [ ] **Step 3: Implement.** `cryptoh/spectral/laplacian.py`:
```python
"""Normalized graph Laplacian via scipy.sparse."""
from __future__ import annotations
import numpy as np
from scipy import sparse
from scipy.sparse.csgraph import laplacian as csgraph_laplacian
from scipy.sparse.linalg import eigsh

def symmetrize(A: sparse.spmatrix) -> sparse.csr_matrix:
    A = sparse.csr_matrix(A, dtype=float)
    return ((A + A.T) * 0.5).tocsr()

def normalized_laplacian(A: sparse.spmatrix) -> sparse.csr_matrix:
    return csgraph_laplacian(symmetrize(A), normed=True).tocsr()

def smallest_eigenpairs(L: sparse.spmatrix, k: int = 8) -> tuple[np.ndarray, np.ndarray]:
    n = L.shape[0]
    k = max(1, min(k, n - 1))
    vals, vecs = eigsh(sparse.csr_matrix(L, dtype=float), k=k, which="SM")
    order = np.argsort(vals)
    return vals[order], vecs[:, order]
```
`cryptoh/spectral/fiedler.py`:
```python
"""Signal 1 — Fiedler value (algebraic connectivity) drop. Fiedler 1973."""
from __future__ import annotations

DEFAULT_DELTA = 0.20

def detect(baseline_lambda2: float, current_lambda2: float, delta: float = DEFAULT_DELTA) -> dict:
    if baseline_lambda2 <= 0:
        return {"fired": False, "score": 0.0, "detail": "no baseline"}
    drop = (baseline_lambda2 - current_lambda2) / baseline_lambda2
    return {"fired": bool(drop > delta), "score": float(max(0.0, min(1.0, drop))), "detail": f"λ2 {baseline_lambda2:.3f} → {current_lambda2:.3f}"}
```
`cryptoh/spectral/multiplicity.py`:
```python
"""Signal 2 — zero-eigenvalue multiplicity spike. Chung 1997."""
from __future__ import annotations
import numpy as np

def multiplicity(eigenvalues: np.ndarray, eps: float = 0.01) -> int:
    return int(np.sum(np.asarray(eigenvalues) < eps))

def detect(baseline_mult: int, current_mult: int) -> dict:
    fired = current_mult > baseline_mult
    return {"fired": bool(fired), "score": 1.0 if fired else 0.0, "detail": f"mult {baseline_mult} → {current_mult}"}
```
`cryptoh/spectral/clustering.py`:
```python
"""Signal 3 — spectral-clustering outlier projection. Ng-Jordan-Weiss 2002."""
from __future__ import annotations
import numpy as np

def outlier_nodes(embedding: np.ndarray, node_ids: list[str], sigma: float = 3.0) -> list[str]:
    X = np.asarray(embedding, dtype=float)
    centroid = X.mean(axis=0)
    dists = np.linalg.norm(X - centroid, axis=1)
    mu, sd = float(dists.mean()), float(dists.std() + 1e-9)
    return [nid for nid, d in zip(node_ids, dists) if d > mu + sigma * sd]

def detect(embedding: np.ndarray, node_ids: list[str]) -> dict:
    out = outlier_nodes(embedding, node_ids)
    return {"fired": len(out) > 0, "score": min(1.0, len(out) / 8.0), "detail": f"{len(out)} outliers", "nodes": out}
```
`cryptoh/spectral/rule.py`:
```python
"""2-of-3 aggregation rule."""
from __future__ import annotations

def combine(signals: list[bool]) -> dict:
    votes = sum(1 for s in signals if s)
    return {"anomaly": votes >= 2, "votes": votes, "signals": list(signals)}
```
`cryptoh/spectral/baseline.py`:
```python
"""Rolling baseline over the first N windows (default 60s / 5s = 12)."""
from __future__ import annotations

class Baseline:
    def __init__(self, warmup_windows: int = 12) -> None:
        self.warmup = warmup_windows
        self.lambda2_history: list[float] = []
        self.mult_history: list[int] = []

    def update(self, lambda2: float, mult: int) -> None:
        self.lambda2_history.append(lambda2)
        self.mult_history.append(mult)

    @property
    def ready(self) -> bool:
        return len(self.lambda2_history) >= self.warmup

    @property
    def lambda2(self) -> float:
        h = self.lambda2_history[: self.warmup]
        return sum(h) / len(h)

    @property
    def mult(self) -> int:
        return self.mult_history[0] if self.mult_history else 1
```
`cryptoh/spectral/__init__.py` re-exports each public symbol.

- [ ] **Step 4: Add remaining detector tests** (`test_fiedler.py`: 0.342→0.087 fires; no-drop does not. `test_multiplicity.py`: 1→4 fires. `test_clustering.py`: 8-node star, center flagged or empty-safe) then run:
Run: `uv run pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**
```bash
git add cryptoh/spectral tests/test_laplacian.py tests/test_fiedler.py tests/test_multiplicity.py tests/test_clustering.py tests/test_rule.py
git commit -m "feat: spectral core with 2-of-3 rule"
```

---
### Task 3: Ingest (window + graph builder + nginx/csv/json sources)

**Files:**
- Create: `cryptoh/ingest/__init__.py`, `cryptoh/ingest/window.py`, `cryptoh/ingest/graph_builder.py`, `cryptoh/ingest/sources/__init__.py`, `cryptoh/ingest/sources/base.py`, `cryptoh/ingest/sources/nginx_access_log.py`, `cryptoh/ingest/sources/csv_file.py`, `cryptoh/ingest/sources/json_stream.py`, `cryptoh/ingest/sources/_template.py`
- Test: `tests/test_sources.py`

- [ ] **Step 1: Write failing test** `tests/test_sources.py`:
```python
from cryptoh.ingest.sources.nginx_access_log import parse_line

def test_parse_combined_log():
    line = '10.0.0.14 - - [05/Oct/2026:10:00:01 +0000] "GET /api/v1/health HTTP/1.1" 200 12 "-" "curl/7.81"'
    edge = parse_line(line)
    assert edge is not None
    assert edge.src == "10.0.0.14"

def test_parse_garbage_returns_none():
    assert parse_line("not a log line") is None
```

- [ ] **Step 2: Run to verify it fails**
Run: `uv run pytest tests/test_sources.py -v`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement.** `sources/base.py`:
```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    weight: float = 1.0
    raw: str = ""

class Source(Protocol):
    name: str
    def edges_from_path(self, path: str): ...
```
`nginx_access_log.py`: regex `^(?P<ip>\S+).*"(?P<method>\S+) (?P<path>\S+)` → `Edge(src=ip, dst=path.split('/')[1] if '/' in path else path, raw=line)`; server-name variant: treat `dst` as request path service token. `csv_file.py`: `src,dst[,weight]` via csv.DictReader. `json_stream.py`: NDJSON `{"src","dst","weight?"}` per line, skip bad lines. `window.py`: `TumblingWindow(seconds)` accumulating edges, `flush() -> list[Edge]`. `graph_builder.py`: `build_matrix(edges) -> (A_csr, node_ids)` with index map; weight = sum.
`_template.py`: 20-line documented starter with `parse_line` + `edges_from_path` TODO-free example (uses `Edge(src="a", dst="b")` echo pattern clearly marked as example code, not placeholder).

- [ ] **Step 4: Run tests**
Run: `uv run pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**
```bash
git add cryptoh/ingest tests/test_sources.py
git commit -m "feat: ingest with nginx csv json sources"
```

---
### Task 4: Extract (subgraph + DOT + PNG)

**Files:**
- Create: `cryptoh/extract/__init__.py`, `cryptoh/extract/subgraph.py`, `cryptoh/extract/dot_render.py`, `cryptoh/extract/png_render.py`
- Test: `tests/test_extract.py`

- [ ] **Step 1: Write failing test**:
```python
from scipy import sparse
import numpy as np
from cryptoh.extract.subgraph import extract
from cryptoh.extract.dot_render import to_dot

def test_extract_caps_k():
    A = sparse.csr_matrix(np.ones((12, 12)) - np.eye(12))
    ids = [f"n{i}" for i in range(12)]
    fiedler = np.arange(12, dtype=float)
    sub = extract(A, ids, fiedler, outlier_nodes=["n3"], k=8)
    assert len(sub["nodes"]) <= 8 and "n3" in sub["nodes"]
    dot = to_dot(sub)
    assert "digraph" in dot and "n3" in dot
```

- [ ] **Step 2: Run, expect FAIL.** Run: `uv run pytest tests/test_extract.py -v`

- [ ] **Step 3: Implement.** `subgraph.py`: score nodes by `|fiedler|` rank, union with outliers, take top-k, return induced `{"nodes", "edges": [(s,d,w)]}`. `dot_render.py`: manual `digraph cryptoh {...}` writer, red color attr on anomalous nodes. `png_render.py`: `matplotlib.use("Agg")`, spring layout with `seed=7`, dark `#0a0a0a` bg, red anomalous edges, `save(path)` returns path.

- [ ] **Step 4: Run tests** `uv run pytest tests/ -v` → PASS.

- [ ] **Step 5: Commit** `git commit -m "feat: anomaly subgraph extract and render"`.

---
### Task 5: LLM layer (prompt + live client + fallback + parser)

**Files:**
- Create: `cryptoh/llm/__init__.py`, `cryptoh/llm/prompts/diagnose.py`, `cryptoh/llm/gemma.py`, `cryptoh/llm/fallback.py`, `cryptoh/llm/parser.py`
- Test: `tests/test_gemma.py`

- [ ] **Step 1: Write failing test**:
```python
from cryptoh.llm.parser import parse_json_response
from cryptoh.llm.fallback import diagnose as fallback_diagnose

def test_parser_handles_fences():
    out = parse_json_response('```json\n{"a": 1}\n```')
    assert out == {"a": 1}

def test_fallback_needs_no_key():
    d = fallback_diagnose(dot="digraph {}", logs=["l1"], spectral_strength=0.7, nodes=["x"])
    assert d["confidence"]["total"] >= 0 and "mitigation" in d
```

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement.** `prompts/diagnose.py`: `DIAGNOSE_PROMPT` template with `{dot} {logs} {spectral_strength}` (PRD §6.2 text). `gemma.py`: lazy `google.genai` import inside function, `diagnose_live(api_key, prompt, png_bytes)` calling `genai.Client(api_key=...).models.generate_content(model="gemma-3-27b-it", contents=[prompt, png_part])`, returns text; raises `RuntimeError` with clear message if lib/key missing. `fallback.py`: deterministic heuristic (beaconing wording if single dominant dst, star wording if fan-out) returning the same JSON shape. `parser.py`: strip fences, `json.loads`, on failure wrap as `{"diagnosis": text, ...}` text-only shape (never raises).

- [ ] **Step 4: Run tests** → PASS (no network, no key).

- [ ] **Step 5: Commit** `git commit -m "feat: gemma llm layer with offline fallback"`.

---
### Task 6: Mitigation validators + templates

**Files:**
- Create: `cryptoh/mitigate/__init__.py`, `cryptoh/mitigate/iptables.py`, `cryptoh/mitigate/docker_policy.py`, `cryptoh/mitigate/k8s_networkpolicy.py`, `cryptoh/mitigate/nginx_config.py`, `cryptoh/mitigate/templates/iptables_drop.j2`, `cryptoh/mitigate/templates/docker_isolate.j2`, `cryptoh/mitigate/templates/k8s_deny.j2`, `cryptoh/mitigate/templates/nginx_ratelimit.j2`
- Test: `tests/test_mitigate.py`

- [ ] **Step 1: Write failing test**:
```python
from cryptoh.mitigate.iptables import validate as v_ipt
from cryptoh.mitigate.nginx_config import validate as v_ngx

def test_iptables_accepts_drop():
    assert v_ipt("iptables -A INPUT -s 10.0.0.14 -j DROP")["valid"] is True

def test_iptables_rejects_flush():
    assert v_ipt("iptables -F")["valid"] is False

def test_nginx_accepts_ratelimit():
    assert v_ngx("limit_req_zone $binary_remote_addr zone=cryptoh:10m rate=5r/s;")["valid"] is True
```

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement.** `iptables.py`: `shlex.split`, must start with `iptables`, `-A` chain in {INPUT,OUTPUT,FORWARD}, `-j` in {DROP,REJECT,ACCEPT,LOG}, `-s/-d` present; reject `-F/-X/-P`. Others: structural checks (docker: `{"action":"isolate","container":...}` JSON shape via jinja render + json.loads; k8s: must contain `kind: NetworkPolicy` + `podSelector`; nginx: must contain `limit_req` or `deny`). Templates are complete jinja files with `{{ attacker_ip }}` / `{{ service }}` vars — no placeholders.

- [ ] **Step 4: Run tests** → PASS.

- [ ] **Step 5: Commit** `git commit -m "feat: mitigation validators and templates"`.

---
### Task 7: Core events + TUI + stub web server

**Files:**
- Create: `cryptoh/core/__init__.py`, `cryptoh/core/events.py`, `cryptoh/core/trace.py`, `cryptoh/tui/__init__.py`, `cryptoh/tui/operator.py`, `cryptoh/tui/confirm.py`, `cryptoh/tui/audit.py`, `cryptoh/web/__init__.py`, `cryptoh/web/server.py`

- [ ] **Step 1: Implement directly (no new behavior to TDD — constructors only).** `events.py`: pydantic `SpectralSignals(lambda2, multiplicity, votes)` and `AnomalyEvent(nodes, signals, diagnosis, mitigation, is_anomaly=True)`. `trace.py`: `TraceRecorder(path)` appends JSON lines. `operator.py`: `show_diagnosis(console, event)` colored panels; `confirm.py`: typer-style `y/N`; `audit.py`: `write_audit(dir, event)` dated NDJSON. `server.py`: FastAPI with `GET /api/v1/health → {"status":"ok"}`, `GET /` serving inline dark HTML stub noting M5 dashboard, `GET /api/v1/detect` returning current stub signals.

- [ ] **Step 2: Smoke check**
Run: `uv run python -c "from cryptoh.web.server import app; print('ok')" && uv run python -c "from cryptoh.core.events import AnomalyEvent; print(AnomalyEvent(nodes=['a'], signals={'votes':2}, diagnosis={}, mitigation={}).is_anomaly)"`
Expected: `ok` then `True`.

- [ ] **Step 3: Commit** `git commit -m "feat: core events tui and health server stub"`.

---
### Task 8: CLI (watch / batch / list) + data + scripts

**Files:**
- Create: `cryptoh/cli.py`, `tests/test_cli.py`, `data/nginx_normal.log`, `data/nginx_c2_attack.log`, `data/README.md`, `scripts/replay-attack.sh`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing test**:
```python
from typer.testing import CliRunner
from cryptoh.cli import app

def test_version():
    assert CliRunner().invoke(app, ["--version"]).exit_code == 0

def test_list_sources():
    r = CliRunner().invoke(app, ["list", "sources"])
    assert r.exit_code == 0 and "nginx" in r.output

def test_batch_detects_c2():
    r = CliRunner().invoke(app, ["batch", "--source", "data/nginx_c2_attack.log", "--no-mitigate"])
    assert r.exit_code == 0 and "ANOMALY" in r.output
```

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement `cli.py`.** typer app: callback shows banner + help; `--version`; `watch --source --model --window --baseline --output-dir --no-mitigate` (tails file, per-window: build matrix → eigsh → 3 signals → rule → on fire: extract, render PNG to output_dir, LLM live-or-fallback, validate mitigation, display, y/N unless --no-mitigate); `batch --source` (single pass over file in window-sized chunks by line count proxy: 200 lines/window, same detect path, writes report dir with `report.md` + PNGs); `list sources|detectors|mitigations` tables. Source arg format `nginx:path` or bare path (nginx default). Keep functions small: `_load_edges(source)`, `_analyze_windows(edges)`, `_handle_anomaly(...)`.

- [ ] **Step 4: Generate data.** `scripts/replay-attack.sh`: cats `data/nginx_c2_attack.log` in 5 chunks with sleep (attack chunk = 47s-interval GETs from 10.0.0.14 → /api/v1/health + evilcdn 443). Normal log: 400 benign lines across 12 services; attack log: same + 60 beacon lines clustered late. `data/README.md`: licenses note (synthetic, Apache-2.0).

- [ ] **Step 5: Run full suite** `uv run pytest tests/ -v` → PASS, then commit `git commit -m "feat: cli watch batch list plus demo data"`.

---
### Task 9: Dockerfile + Render + lint + full verify

**Files:**
- Create: `Dockerfile`, `render.yaml`

- [ ] **Step 1: Write `Dockerfile`** (exact):
```dockerfile
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY cryptoh/ ./cryptoh/
COPY README.md LICENSE ./
EXPOSE 8000
CMD ["uv", "run", "uvicorn", "cryptoh.web.server:app", "--host", "0.0.0.0", "--port", "8000"]
```
`render.yaml` per PRD §13.1 (docker, free, healthCheckPath `/api/v1/health`).

- [ ] **Step 2: Generate lockfile + lint + test**
Run: `uv lock && uv run ruff check cryptoh tests && uv run pytest tests/ -q`
Expected: all green.

- [ ] **Step 3: Docker build**
Run: `docker build -t cryptoh:0.1.0 . 2>&1 | tail -3`
Expected: `Successfully tagged cryptoh:0.1.0`.

- [ ] **Step 4: Commit**
```bash
git add Dockerfile render.yaml uv.lock
git commit -m "feat: dockerfile and render blueprint"
```

## Self-Review
- Spec §2 pipeline → Tasks 2–8 each map; §3 per-file → exact paths above; §4 flow → Task 8 `_analyze_windows`; §5 errors → Tasks 2 (baseline gate), 5 (parser fallback), 6 (⚠ UNVALIDATED), 8 (`--no-mitigate`); §6 tests → every task has tests runnable keyless; §7 packaging → Tasks 1, 9.
- No TBD/TODO/placeholder text; every code step shows real code; type names consistent (`Edge`, `Baseline`, `combine`, `extract`, `to_dot`, `parse_json_response`, `validate`).
- Fix applied inline: added stub `cryptoh/web/server.py` (Task 7) so Dockerfile CMD + Render health check resolve before M5.
