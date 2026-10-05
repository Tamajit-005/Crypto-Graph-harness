"""Docker mitigation policy validator — JSON shape check."""
from __future__ import annotations

import json

_ACTIONS = {"isolate", "disconnect", "block"}


def validate(script: str) -> dict:
    """Validate a JSON docker-mitigation policy. Returns {"valid", "reason"}; never raises."""
    try:
        doc = json.loads(script)
    except (json.JSONDecodeError, TypeError) as exc:
        return {"valid": False, "reason": f"invalid JSON: {exc}"}
    if not isinstance(doc, dict):
        return {"valid": False, "reason": "policy must be a JSON object"}
    if doc.get("action") not in _ACTIONS:
        return {"valid": False, "reason": f"unsupported action: {doc.get('action')!r}"}
    container = doc.get("container")
    if not isinstance(container, str) or not container.strip():
        return {"valid": False, "reason": "missing non-empty container"}
    return {"valid": True, "reason": "ok"}
