"""Compliance-grade NDJSON audit log."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cryptoh.core.trace import TraceRecorder


def write_audit(directory: str | Path, event) -> str:
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    path = Path(directory) / f"audit-{day}.ndjson"
    data = event.model_dump() if hasattr(event, "model_dump") else dict(event)
    TraceRecorder(path).record("anomaly_event", data)
    return str(path)
