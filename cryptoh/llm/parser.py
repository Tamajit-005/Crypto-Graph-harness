"""Parse Gemma JSON responses. Never raises — falls back to text shape."""
from __future__ import annotations

import json


def parse_json_response(text: str) -> dict:
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.lower().startswith("json"):
            t = t[4:]
        t = t.strip()
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    return {
        "diagnosis": text.strip(),
        "root_cause": "unparsed — review raw output",
        "confidence": {"spectral": 0.0, "log": 0.0, "total": 0.0},
        "mitigation": {"type": "none", "script": "", "explanation": "No structured mitigation returned."},
    }
