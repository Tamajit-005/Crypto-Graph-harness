"""Signal 3 — spectral-clustering outlier projection. Ng-Jordan-Weiss 2002."""
from __future__ import annotations

import numpy as np


def outlier_nodes(embedding: np.ndarray, node_ids: list[str], sigma: float = 3.0) -> list[str]:
    X = np.asarray(embedding, dtype=float)
    centroid = X.mean(axis=0)
    dists = np.linalg.norm(X - centroid, axis=1)
    mu, sd = float(dists.mean()), float(dists.std())
    sd = max(sd, 1e-3)  # floor: never flag pure floating-point jitter
    return [nid for nid, d in zip(node_ids, dists) if d > mu + sigma * sd]

def detect(embedding: np.ndarray, node_ids: list[str]) -> dict:
    out = outlier_nodes(embedding, node_ids)
    return {"fired": len(out) > 0, "score": min(1.0, len(out) / 8.0), "detail": f"{len(out)} outliers", "nodes": out}
