"""Signal 2 — zero-eigenvalue multiplicity spike. Chung 1997."""
from __future__ import annotations

import numpy as np


def multiplicity(eigenvalues: np.ndarray, eps: float = 0.01) -> int:
    return int(np.sum(np.asarray(eigenvalues) < eps))

def detect(baseline_mult: int, current_mult: int) -> dict:
    fired = current_mult > baseline_mult
    return {"fired": bool(fired), "score": 1.0 if fired else 0.0, "detail": f"mult {baseline_mult} → {current_mult}"}
