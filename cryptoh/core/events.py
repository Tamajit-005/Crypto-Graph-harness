"""Pydantic event types for anomaly pipeline."""
from __future__ import annotations

from pydantic import BaseModel, Field


class SpectralSignals(BaseModel):
    lambda2: float = 0.0
    multiplicity: int = 1
    votes: int = 0
    signals: list[bool] = Field(default_factory=list)


class AnomalyEvent(BaseModel):
    nodes: list[str] = Field(default_factory=list)
    edges: list[tuple[str, str, float]] = Field(default_factory=list)
    signals: dict = Field(default_factory=dict)
    diagnosis: dict = Field(default_factory=dict)
    mitigation: dict = Field(default_factory=dict)
    dot: str = ""
    png_path: str = ""
    is_anomaly: bool = True
    model_config = {"arbitrary_types_allowed": True}
