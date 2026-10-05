"""FastAPI server: API routes, SSE stream, and static dashboard."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from cryptoh.web import state
from cryptoh.web.routes.detect import router as detect_router
from cryptoh.web.routes.diagnose import router as diagnose_router
from cryptoh.web.routes.mitigate import router as mitigate_router

app = FastAPI(title="cryptoh")

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(detect_router)
app.include_router(diagnose_router)
app.include_router(mitigate_router)


@app.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "version": "0.1.0"}


def _sse_format(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


async def _event_generator():
    last = {}
    while True:
        snap = {
            "anomaly": state.last_detection.get("anomaly"),
            "votes": state.last_detection.get("votes", 0),
            "signals": state.last_detection.get("signals", {}),
            "windows": state.last_detection.get("windows", 0),
            "anomalies": state.last_detection.get("anomalies", 0),
            "note": state.last_detection.get("note", ""),
        }
        if snap != last:
            last = snap
            yield _sse_format("window", {
                "window": snap.get("windows", 0),
                "lambda2": snap.get("signals", {}).get("lambda2", 0.0),
                "mult": snap.get("signals", {}).get("multiplicity", 1),
                "votes": snap.get("votes", 0),
                "status": "ANOMALY" if snap.get("anomaly") else "normal",
            })
            for aid, item in state.mitigations.items():
                if item.get("_emitted"):
                    continue
                item["_emitted"] = True
                yield _sse_format("anomaly", {
                    "window": snap.get("windows", 0),
                    "nodes": item.get("nodes", []),
                    "signals": {"lambda2": snap.get("signals", {}).get("lambda2", 0.0),
                                "multiplicity": snap.get("signals", {}).get("multiplicity", 1),
                                "votes": snap.get("votes", 0)},
                    "mitigation_id": aid,
                })
        await asyncio.sleep(1.0)


@app.get("/api/v1/stream")
def stream() -> StreamingResponse:
    return StreamingResponse(_event_generator(), media_type="text/event-stream")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    p = static_dir / "index.html"
    return p.read_text(encoding="utf-8") if p.exists() else (
        "<html><body><h1 style='color:#00ffff;background:#0a0a0a;font-family:monospace'>"
        "cryptoh dashboard</h1></body></html>"
    )
