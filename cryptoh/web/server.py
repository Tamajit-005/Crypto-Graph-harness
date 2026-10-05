"""FastAPI server: API routes, SSE stream, and static dashboard."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from cryptoh.web import state
from cryptoh.web.routes.detect import router as detect_router
from cryptoh.web.routes.diagnose import router as diagnose_router
from cryptoh.web.routes.mitigate import router as mitigate_router
from cryptoh.web.tailer import tailer_from_env

# Single shared tailer, created on startup when a source is configured.
_tailer: list = []


@asynccontextmanager
async def lifespan(_app: FastAPI):
    tailer = tailer_from_env()
    if tailer is not None:
        _tailer.append(tailer)
        await tailer.start()
    try:
        yield
    finally:
        if _tailer:
            await _tailer[0].stop()
            _tailer.clear()

app = FastAPI(title="cryptoh", lifespan=lifespan)

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(detect_router)
app.include_router(diagnose_router)
app.include_router(mitigate_router)


@app.get("/api/v1/health")
def health() -> dict:
    tailer = _tailer[0] if _tailer else None
    return {
        "status": "ok",
        "version": "0.1.0",
        "live_ingestion": bool(tailer and tailer.running),
        "following": tailer.followed if tailer else [],
    }


def _sse_format(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


def _state_events(last: dict) -> list[tuple[str, dict]]:
    """Diff server state into SSE (event, payload) pairs. Mutates `last`."""
    snap = {
        "anomaly": state.last_detection.get("anomaly"),
        "votes": state.last_detection.get("votes", 0),
        "signals": state.last_detection.get("signals", {}),
        "windows": state.last_detection.get("windows", 0),
        "anomalies": state.last_detection.get("anomalies", 0),
        "note": state.last_detection.get("note", ""),
    }
    if snap == last:
        return []
    last.clear()
    last.update(snap)
    events: list[tuple[str, dict]] = [("window", {
        "window": snap.get("windows", 0),
        "lambda2": snap.get("signals", {}).get("lambda2", 0.0),
        "mult": snap.get("signals", {}).get("multiplicity", 1),
        "votes": snap.get("votes", 0),
        "status": "ANOMALY" if snap.get("anomaly") else "normal",
        "live": False,
    })]
    for aid, item in state.mitigations.items():
        if item.get("_emitted"):
            continue
        item["_emitted"] = True
        # diagnosis travels with the event: the dashboard renders it directly and
        # the confetti threshold reads confidence.total from the stream.
        events.append(("anomaly", {
            "window": snap.get("windows", 0),
            "nodes": item.get("nodes", []),
            "dot": item.get("dot", ""),
            "diagnosis": item.get("diagnosis", {}),
            "mitigation": {
                "type": item.get("type", ""),
                "script": item.get("script", ""),
                "explanation": item.get("explanation", ""),
                "validated": item.get("validated", False),
            },
            "signals": {"lambda2": snap.get("signals", {}).get("lambda2", 0.0),
                        "multiplicity": snap.get("signals", {}).get("multiplicity", 1),
                        "votes": snap.get("votes", 0)},
            "mitigation_id": aid,
        }))
    return events


async def _event_generator():
    """SSE feed: live tailer events when ingestion is on, else state diffing."""
    tailer = _tailer[0] if _tailer else None
    queue = tailer.subscribe() if tailer is not None else None
    last: dict = {}
    try:
        while True:
            if queue is not None:
                try:
                    event, payload = await asyncio.wait_for(queue.get(), timeout=1.0)
                except TimeoutError:
                    for name, data in _state_events(last):
                        yield _sse_format(name, data)
                    continue
                yield _sse_format(event, payload)
                continue
            for name, data in _state_events(last):
                yield _sse_format(name, data)
            await asyncio.sleep(1.0)
    finally:
        if queue is not None and tailer is not None:
            tailer.unsubscribe(queue)


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
