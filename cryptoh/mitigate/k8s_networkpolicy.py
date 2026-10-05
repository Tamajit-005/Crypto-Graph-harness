"""Kubernetes NetworkPolicy validator — structural text check (schema validation is M6 scope)."""
from __future__ import annotations


def validate(script: str) -> dict:
    """Check the manifest declares a NetworkPolicy with a podSelector. Never raises."""
    if not isinstance(script, str):
        return {"valid": False, "reason": "input must be a string"}
    text = script
    if "kind: NetworkPolicy" not in text:
        return {"valid": False, "reason": "missing kind: NetworkPolicy"}
    if "podSelector" not in text:
        return {"valid": False, "reason": "missing podSelector"}
    return {"valid": True, "reason": "ok"}
