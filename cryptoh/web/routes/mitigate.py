"""GET /api/v1/mitigate/{anomaly_id} — fetch a stored mitigation script."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from cryptoh.web import state

router = APIRouter()


@router.get("/api/v1/mitigate/{anomaly_id}")
def mitigate(anomaly_id: str) -> dict:
    item = state.mitigations.get(anomaly_id)
    if item is None:
        raise HTTPException(status_code=404, detail="unknown anomaly id")
    return {"id": anomaly_id, **item,
            "notice": "review before applying — scripts are never applied automatically"}
