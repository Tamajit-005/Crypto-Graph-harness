"""Build sparse adjacency matrix from edges."""

from __future__ import annotations

from scipy import sparse

from cryptoh.ingest.sources.base import Edge


def build_matrix(edges: list[Edge]) -> tuple[sparse.csr_matrix, list[str]]:
    nodes = sorted({e.src for e in edges} | {e.dst for e in edges})
    idx = {n: i for i, n in enumerate(nodes)}
    rows = [idx[e.src] for e in edges]
    cols = [idx[e.dst] for e in edges]
    data = [float(e.weight) for e in edges]
    A = sparse.csr_matrix((data, (rows, cols)), shape=(len(nodes), len(nodes)), dtype=float)
    A.sum_duplicates()
    return A, nodes
