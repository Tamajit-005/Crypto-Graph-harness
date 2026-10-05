### The Everyday Scenario: A Silent Microservice Outage

Imagine you run an e-commerce platform with 50 Docker containers talking across a Kubernetes cluster or Docker network:

* Service A (`api-gateway`)
* Service B (`auth-service`)
* Service C (`billing-service`)
* Service D (`inventory-db`)
* ...plus 46 other background workers.

Suddenly, users report that checkout is timing out. You open your terminal and check your NGINX ingress and Docker network logs. There are **100,000 log lines per minute**:

```log
[10:14:01] 10.0.0.12 -> 10.0.0.45 : POST /cart/checkout 200 OK (12ms)
[10:14:01] 10.0.0.45 -> 10.0.0.88 : GET /inventory/check 200 OK (4ms)
[10:14:02] 10.0.0.12 -> 10.0.0.99 : POST /analytics/event 200 OK (2ms)
[10:14:02] 10.0.0.33 -> 10.0.0.71 : GET /user/profile 200 OK (5ms)
... (99,996 more lines of completely normal HTTP 200s)

```

There are no error codes, no stack traces, and no `500 Internal Server Error` banners. A malicious container or a deadlocked worker is subtly pinging an external server or causing a silent traffic leak.

---

### What happens if you use standard tools?

* **Standard LLM / Codex:** You cannot feed 100,000 log lines into an LLM context window. Even if you chunk it, an LLM reading line by line sees valid `200 OK` JSON requests. It will hallucinate or output generic advice like *"Check your network timeout settings."*
* **Graphify:** Graphify looks at your repository on disk. It checks your source code: `routes/checkout.ts`, `services/billing.py`. Graphify will tell you: *"Yes, `billing.py` imports `database.py`."* But your source code isn't broken—the live cluster traffic is broken. Graphify cannot see live sockets or container packets.

---

### How Crypto-Graph Solves This (Step-by-Step Developer Flow)

The Crypto-Graph Harness is a **runtime proxy script** that sits between your live logs and Gemma 4.

```
           [100,000 Raw Log Lines]
                      │
                      ▼
 1. Parse IPs into an Adjacency Matrix (A)
    ┌──────────┬──────────┬──────────┐
    │          │ 10.0.0.1 │ 10.0.0.2 │
    ├──────────┼──────────┼──────────┤
    │ 10.0.0.1 │    0     │   142    │  (142 packets sent)
    │ 10.0.0.2 │   142    │    0     │
    └──────────┴──────────┴──────────┘
                      │
                      ▼
 2. Compute Laplacian Matrix: L = D - A
    Calculate Eigenvalues via `scipy.linalg.eigh(L)`
    (Takes ~25 milliseconds for 5,000 nodes)
                      │
                      ▼
 3. Eigenvector Anomaly Isolation:
    - Normal mesh traffic clusters around eigenvalue λ ≈ 0.4 - 1.2
    - Outlier cluster spotted at λ ≈ 0.003!
    - Math automatically isolates ONLY the 3 guilty nodes:
      [10.0.0.45, 10.0.0.88, 198.51.100.4]
                      │
                      ▼
 4. Harness Generates:
    - A 2KB PNG diagram of the 3 isolated nodes
    - The exact 12 log lines between these 3 nodes
                      │
                      ▼
 5. Send PNG + 12 lines to Gemma 4 via Gemini API[cite: 1]
                      │
                      ▼
 6. Gemma 4 Output in your Terminal:
    "Root cause: Container 10.0.0.45 is caught in an unauthorized 
     retry storm with external IP 198.51.100.4.
     Remediation: Run `iptables -A OUTPUT -d 198.51.100.4 -j DROP`"

```

---

### The Code Example: What You Actually Build in 6 Hours

You can write this entire working prototype in roughly 60 lines of clean Python.

```python
import networkx as nx
import numpy as np
import scipy.sparse.csgraph as csgraph
import matplotlib.pyplot as plt
import google.genai as genai

# 1. Ingest raw runtime connection stream
raw_logs = [
    ("api-gateway", "auth-service", 50),
    ("auth-service", "user-db", 48),
    ("api-gateway", "inventory", 30),
    ("inventory", "inventory-db", 28),
    # The anomaly: two internal services silently exfiltrating to an unknown IP
    ("auth-service", "rogue-external-ip", 120),
    ("inventory", "rogue-external-ip", 115),
]

# 2. Build the Graph
G = nx.Graph()
for src, dst, weight in raw_logs:
    G.add_edge(src, dst, weight=weight)

# 3. Deterministic Spectral Math (Laplacian Eigenvalues)
nodes = list(G.nodes())
A = nx.to_numpy_array(G)
L = csgraph.laplacian(A, normed=True)
eigenvalues, eigenvectors = np.linalg.eigh(L)

# Mathematical detection: Find the Fiedler vector (2nd smallest eigenvalue)
fiedler_vector = eigenvectors[:, 1]
suspicious_indices = np.where(fiedler_vector > 0.3)[0]
bad_nodes = [nodes[i] for i in suspicious_indices]

# 4. Render a focused visual artifact for multimodal Gemma 4
subgraph = G.subgraph(bad_nodes)
plt.figure(figsize=(4, 3))
nx.draw(subgraph, with_labels=True, node_color='red', font_weight='bold')
plt.savefig("/tmp/subgraph_anomaly.png")

# 5. Multimodal Agent Tool Call: Send image + minimal context to Gemma 4
client = genai.Client()
response = client.models.generate_content(
    model="gemma-4-26b-a4b-it", # Gemma 4 26B (AI Studio) multimodal model via the Gemini API
    contents=[
        genai.types.Part.from_bytes(
            data=open("/tmp/subgraph_anomaly.png", "rb").read(),
            mime_type="image/png"
        ),
        f"Spectral graph analysis isolated these anomalous interacting nodes: {bad_nodes}. "
        # Crypto-Graph Harness

        Crypto-Graph Harness is a Python 3.11+ CLI and FastAPI service for finding
        structural anomalies in runtime telemetry. It converts communication records
        into weighted graphs, analyzes normalized Laplacian signals, extracts a small
        anomaly subgraph, and produces operator-facing diagnosis and mitigation output.

        The repository includes synthetic NGINX access-log fixtures and a complete demo
        that exercises batch detection, optional Gemma diagnosis, mitigation validation,
        and the live dashboard.

        ## How It Works

        The shared pipeline is:

        ```text
        telemetry source -> weighted interaction graph -> tumbling windows
                -> normalized Laplacian -> three detectors -> 2-of-3 decision
                -> anomaly subgraph -> DOT/PNG -> diagnosis -> validated mitigation
        ```

        The detectors are:

        - Fiedler signal: detects a change in algebraic connectivity (`lambda_2`).
        - Multiplicity signal: detects an unusual number of near-zero eigenvalues.
        - Clustering signal: finds outliers in the spectral embedding.

        An anomaly requires at least two of the three signals. Anomalies produce a
        focused subgraph, Graphviz DOT, a PNG topology image, scrubbed log context, an
        operator diagnosis, and an audit record. The model step is optional: without a
        `GEMINI_API_KEY`, the built-in deterministic heuristic still produces a usable
        diagnosis and fallback `iptables` mitigation.

        ## Requirements

        - Python 3.11 or newer
        - [`uv`](https://docs.astral.sh/uv/)
        - Graphviz is recommended for local graph tooling; PNG rendering uses the
            Python plotting dependencies installed by `uv`.
        - A Gemini API key is optional. The offline fallback is used when it is absent
            or when a model request fails.

        ## Installation

        ```bash
        uv sync
        uv run cryptoh --version
        ```

        For local configuration, copy `.env.example` to `.env` and set a key when
        model-backed diagnosis is wanted:

        ```bash
        cp .env.example .env
        export GEMINI_API_KEY="your-key"
        ```

        `.env` is local configuration and must not be committed.

        ## Quick Start

        Run batch analysis against the included benign fixture:

        ```bash
        uv run cryptoh batch --source data/nginx_normal.log --no-mitigate
        ```

        Run the attack fixture and write report artifacts to a temporary directory:

        ```bash
        uv run cryptoh batch \
            --source data/nginx_c2_attack.log \
            --output-dir /tmp/cryptoh-demo
        ```

        The output directory can contain `report.md` and anomaly PNGs. Anomaly
        diagnosis also writes NDJSON records under `cryptoh-audit/` unless `--dry-run`
        is used.

        ## Full Demo

        The checked-in `scripts/demo.sh` runs four stages:

        1. Verifies benign traffic remains quiet.
        2. Detects the synthetic C2 attack using the 2-of-3 rule.
        3. Runs Gemma diagnosis when configured, otherwise uses the offline fallback.
        4. Starts the live dashboard, tails a real file, and injects attack traffic.

        ```bash
        ./scripts/demo.sh
        ```

        Useful options:

        ```bash
        ./scripts/demo.sh --no-ui             # terminal pipeline only
        ./scripts/demo.sh --no-model          # skip model calls
        ./scripts/demo.sh --port 8011         # use another dashboard port
        ./scripts/demo.sh --hold 0            # stop after the dashboard check
        ```

        With the UI enabled, open `http://127.0.0.1:8000/`. The script prints the
        temporary log and report locations and cleans up the server on exit.

        ## CLI Commands

        ```bash
        uv run cryptoh list sources
        uv run cryptoh list detectors
        uv run cryptoh list mitigations
        uv run cryptoh batch --source data/nginx_c2_attack.log
        uv run cryptoh watch --source data/nginx_c2_attack.log --from-end
        uv run cryptoh calibrate --source data/nginx_normal.log
        uv run cryptoh export stix --source data/nginx_c2_attack.log
        uv run cryptoh serve --host 127.0.0.1 --port 8000
        ```

        `batch` and `watch` accept `--window`, `--baseline`, `--output-dir`,
        `--adaptive-baseline`, `--dry-run`, `--compare`, and `--feedback`. Source
        paths can be prefixed explicitly, for example
        `--source nginx:data/nginx_normal.log`.

        Supported source adapters are:

        | Adapter | Typical input |
        | --- | --- |
        | `nginx` | NGINX access logs |
        | `csv` | CSV edge records |
        | `json` | JSON stream records |
        | `docker` | Docker bridge flow records |
        | `ebpf` | eBPF socket traces |
        | `vpc` | VPC flow logs |
        | `pcap` | Packet captures |
        | `syslog` | Syslog/UDP records |

        ## Dashboard API

        Start the service with `uv run cryptoh serve` or run the Docker image. The
        FastAPI application provides:

        - `GET /api/v1/health` for version and live-ingestion status.
        - `GET /api/v1/detect` for the current detection snapshot.
        - `POST /api/v1/diagnose` to analyze posted `edges` or parse posted NGINX
            `logs`; use `wait=true` for a synchronous response.
        - `GET /api/v1/diagnose/{job_id}` to poll an asynchronous diagnosis job.
        - `GET /api/v1/stream` for server-sent detection and mitigation events.
        - `GET /` for the static operator dashboard.

        The live tailer is enabled by setting `CRYPTOH_SOURCE` to a supported source
        file before starting Uvicorn:

        ```bash
        CRYPTOH_SOURCE=/path/to/access.log \
            uv run uvicorn cryptoh.web.server:app --host 127.0.0.1 --port 8000
        ```

        ## Mitigation and Safety

        Supported mitigation backends are `iptables`, `docker`, `k8s`, and `nginx`.
        Generated scripts are validated before they are presented. The CLI asks for
        operator confirmation before applying a mitigation in an interactive terminal;
        the demo automatically answers no. Use `--no-mitigate` or `--dry-run` when
        testing detection only.

        ## Docker

        Build and run the dashboard:

        ```bash
        docker build -t cryptoh .
        docker run --rm -p 8000:8000 cryptoh
        ```

        The image starts `uvicorn cryptoh.web.server:app` on port 8000.

        ## Development

        Run the test suite and lint checks with:

        ```bash
        uv run pytest
        uv run ruff check .
        ```

        Useful implementation guides are in `docs/`, including the architecture,
        spectral signals, adapter contract, model payload, mitigation safety, and
        calibration notes. The source is organized into `cryptoh/ingest`,
        `cryptoh/spectral`, `cryptoh/extract`, `cryptoh/llm`, `cryptoh/mitigate`,
        `cryptoh/tui`, `cryptoh/web`, and `cryptoh/core`.

        ## License

        Apache-2.0. See [LICENSE](LICENSE).