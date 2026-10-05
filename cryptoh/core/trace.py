"""NDJSON trace recorder."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


class TraceRecorder:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event_type: str, payload: dict) -> None:
        rec = {"ts": datetime.now(UTC).isoformat(), "type": event_type, **payload}
        with self.path.open("a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
