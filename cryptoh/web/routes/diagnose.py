"""POST /api/v1/diagnose — analyze posted edges end to end."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from cryptoh.web.service import diagnose_edges

router = APIRouter()


class DiagnoseRequest(BaseModel):
    edges: list[dict] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)


@router.post("/api/v1/diagnose")
def diagnose(req: DiagnoseRequest) -> dict:
    items = list(req.edges)
    if req.logs and not items:
        from cryptoh.ingest.sources.nginx_access_log import parse_line

        for line in req.logs:
            edge = parse_line(line)
            if edge is not None:
                items.append({"src": edge.src, "dst": edge.dst,
                              "weight": edge.weight, "raw": edge.raw})
    return diagnose_edges(items)
