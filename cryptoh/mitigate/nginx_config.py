"""nginx mitigation snippet validator — rate-limit / deny allowlist."""
from __future__ import annotations


def validate(script: str) -> dict:
    """Validate an nginx mitigation snippet. Returns {"valid", "reason"}; never raises."""
    if not isinstance(script, str):
        return {"valid": False, "reason": "input must be a string"}
    text = script
    if "lua_" in text:
        return {"valid": False, "reason": "lua_ directives unsupported"}
    if "limit_req" not in text and "deny" not in text:
        return {"valid": False, "reason": "missing limit_req or deny directive"}
    return {"valid": True, "reason": "ok"}
