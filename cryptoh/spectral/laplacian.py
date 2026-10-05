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
    vals, vecs = eigsh(sparse.csr_matrix(L, dtype=float), k=k, which="SM")
    order = np.argsort(vals)
    return vals[order], vecs[:, order]
