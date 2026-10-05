"""In-memory server state: latest detection snapshot and mitigation store."""

from __future__ import annotations

import itertools

last_detection: dict = {
    "anomaly": False,
    "votes": 0,
    "signals": {},
    "windows": 0,
    "anomalies": 0,
    "note": "no telemetry analyzed yet — POST edges to /api/v1/diagnose",
}

mitigations: dict[str, dict] = {}
_ids = itertools.count(1)


def next_id() -> str:
    return f"a{next(_ids)}"
