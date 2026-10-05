"""Normalized graph Laplacian via scipy.sparse."""
from __future__ import annotations

import numpy as np
from scipy import sparse
from scipy.sparse.csgraph import laplacian as csgraph_laplacian
from scipy.sparse.linalg import eigsh


def symmetrize(A: sparse.spmatrix) -> sparse.csr_matrix:
    A = sparse.csr_matrix(A, dtype=float)
    return ((A + A.T) * 0.5).tocsr()

def normalized_laplacian(A: sparse.spmatrix) -> sparse.csr_matrix:
    return csgraph_laplacian(symmetrize(A), normed=True).tocsr()

def smallest_eigenpairs(L: sparse.spmatrix, k: int = 8) -> tuple[np.ndarray, np.ndarray]:
    n = L.shape[0]
    k = max(1, min(k, n - 1))
    M = sparse.csr_matrix(L, dtype=float)
    try:
        vals, vecs = eigsh(M, k=k, which="SM")
    except Exception:
        # Small, degenerate, or non-convergent cases: dense symmetric solver.
        dense = M.toarray()
        dense = (dense + dense.T) * 0.5
        vals_all, vecs_all = np.linalg.eigh(dense)
        vals, vecs = vals_all[:k], vecs_all[:, :k]
    order = np.argsort(vals)
    vals = np.clip(vals[order], 0.0, 2.0)
    return vals, vecs[:, order]
