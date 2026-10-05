"""k-node anomaly subgraph extraction from the anomalous eigenspace."""
from __future__ import annotations

import numpy as np
from scipy import sparse


def extract(
    A: sparse.csr_matrix,
    node_ids: list[str],
    fiedler_vector: np.ndarray,
    outlier_nodes: list[str] | None = None,
    k: int = 8,
) -> dict:
    """Score nodes by |Fiedler| rank, union with outliers, cap at k. Returns induced subgraph dict."""
    scores = np.abs(np.asarray(fiedler_vector, dtype=float))
    ranked = [node_ids[i] for i in np.argsort(scores)[::-1]]
    chosen: list[str] = []
    for nid in list(outlier_nodes or []) + ranked:
        if nid in node_ids and nid not in chosen:
            chosen.append(nid)
        if len(chosen) >= k:
            break
    keep = set(chosen)
    A = A.tocsr()
    edges: list[tuple[str, str, float]] = []
    coo = A.tocoo()
    for r, c, w in zip(coo.row, coo.col, coo.data):
        s, d = node_ids[r], node_ids[c]
        if s in keep and d in keep and w != 0:
            edges.append((s, d, float(w)))
    return {"nodes": chosen, "edges": edges}
