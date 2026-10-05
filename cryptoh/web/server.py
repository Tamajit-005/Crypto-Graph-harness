"""Lightweight API + dashboard server. Serves /api/v1/* and the static dashboard."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="cryptoh")


@app.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/v1/detect")
def detect() -> dict:
    return {"anomaly": False, "votes": 0, "signals": [], "note": "no live stream running"}


DASHBOARD_STUB = """<!doctype html><html><head><title>cryptoh</title></head>
<body style="background:#0a0a0a;color:#e6e6e6;font-family:monospace">
<h1 style="color:#00ffff">Crypto-Graph Harness</h1>
<p>Live dashboard coming soon. API: <a style="color:#ff00ff" href="/api/v1/health">/api/v1/health</a></p>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return DASHBOARD_STUB
