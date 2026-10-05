"""Signal 1 — Fiedler value (algebraic connectivity) drop. Fiedler 1973."""
from __future__ import annotations

DEFAULT_DELTA = 0.20

def detect(baseline_lambda2: float, current_lambda2: float, delta: float = DEFAULT_DELTA) -> dict:
    if baseline_lambda2 <= 0:
        return {"fired": False, "score": 0.0, "detail": "no baseline"}
    drop = (baseline_lambda2 - current_lambda2) / baseline_lambda2
    return {"fired": bool(drop > delta), "score": float(max(0.0, min(1.0, drop))), "detail": f"λ2 {baseline_lambda2:.3f} → {current_lambda2:.3f}"}
