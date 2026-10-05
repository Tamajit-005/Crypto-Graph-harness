"""GET /api/v1/detect — current spectral signal snapshot."""

from __future__ import annotations

from fastapi import APIRouter

from cryptoh.web import state

router = APIRouter()


@router.get("/api/v1/detect")
def detect() -> dict:
    return dict(state.last_detection)
