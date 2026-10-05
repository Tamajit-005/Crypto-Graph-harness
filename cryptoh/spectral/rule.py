"""2-of-3 aggregation rule."""
from __future__ import annotations


def combine(signals: list[bool]) -> dict:
    votes = sum(1 for s in signals if s)
    return {"anomaly": votes >= 2, "votes": votes, "signals": list(signals)}
