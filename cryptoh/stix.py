"""STIX 2.1 exporter for anomaly events."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


def to_stix(event, bundle_id: str = "bundle--cryptoh") -> dict:
    now = datetime.now(UTC).isoformat()
    obj = {
        "type": "bundle",
        "id": bundle_id,
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--cryptoh-anomaly",
                "created": now,
                "modified": now,
                "name": "Spectral graph anomaly",
                "pattern": "[file:hashes.MD5 = 'cryptoh-spectral-anomaly']",
                "valid_from": now,
                "labels": ["anomaly"],
                "extensions": {
                    "cryptoh": {
                        "nodes": list(getattr(event, "nodes", []) or []),
                        "signals": dict(getattr(event, "signals", {}) or {}),
                        "diagnosis": dict(getattr(event, "diagnosis", {}) or {}),
                        "mitigation": dict(getattr(event, "mitigation", {}) or {}),
                        "dot": str(getattr(event, "dot", "") or ""),
                        "png_path": str(getattr(event, "png_path", "") or ""),
                        "feedback": str(getattr(event, "feedback", "") or ""),
                    }
                },
            }
        ],
    }
    return obj


def write_stix(path: str | Path, event) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(to_stix(event), indent=2) + "\n", encoding="utf-8")
    return str(p)
