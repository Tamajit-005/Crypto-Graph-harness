"""POST /api/v1/diagnose — analyze posted edges end to end.

Analysis (spectral pass + optional model call) can take seconds, so it runs as a
background job: the POST returns 202 with a job id immediately and the client
polls GET /api/v1/diagnose/{job_id}. Pass wait=true to keep the old synchronous
contract for scripts and tests.
"""
from __future__ import annotations

import asyncio
import itertools
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from cryptoh.web.service import diagnose_edges

router = APIRouter()

_jobs: dict[str, dict] = {}
_job_ids = itertools.count(1)
_MAX_JOBS = 50


class DiagnoseRequest(BaseModel):
    edges: list[dict] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)


def _edges_from_request(req: DiagnoseRequest) -> list[dict]:
    items = list(req.edges)
    if req.logs and not items:
        from cryptoh.ingest.sources.nginx_access_log import parse_line

        for line in req.logs:
            edge = parse_line(line)
            if edge is not None:
                items.append({"src": edge.src, "dst": edge.dst,
                              "weight": edge.weight, "raw": edge.raw})
    return items


def _run_job(job_id: str, items: list[dict]) -> None:
    _jobs[job_id]["status"] = "running"
    try:
        result = diagnose_edges(items)
        _jobs[job_id].update(status="done", result=result)
    except Exception as exc:  # noqa: BLE001 - a failed job must not kill the server
        _jobs[job_id].update(status="error", result={"ok": False, "error": str(exc)})
    if len(_jobs) > _MAX_JOBS:
        for stale in list(_jobs)[:-_MAX_JOBS]:
            _jobs.pop(stale, None)


@router.post("/api/v1/diagnose")
async def diagnose(req: DiagnoseRequest, wait: bool = Query(default=False)) -> Any:
    items = _edges_from_request(req)
    if len(items) < 12:
        return {"ok": False, "error": "post at least 12 edges with src/dst"}
    if wait:
        return await asyncio.to_thread(diagnose_edges, items)
    job_id = f"job{next(_job_ids)}"
    _jobs[job_id] = {"status": "queued", "submitted": len(items)}
    asyncio.get_running_loop().run_in_executor(None, _run_job, job_id, items)
    return JSONResponse(
        status_code=202,
        content={"job_id": job_id, "status": "queued",
                 "poll": f"/api/v1/diagnose/{job_id}", "edges": len(items)},
    )


@router.get("/api/v1/diagnose/{job_id}")
def diagnose_status(job_id: str) -> Any:
    job = _jobs.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"error": "unknown job id"})
    return job