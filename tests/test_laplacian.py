import numpy as np
from scipy import sparse

from cryptoh.spectral.laplacian import normalized_laplacian, smallest_eigenpairs


def test_normalized_laplacian_path_graph():
    A = sparse.csr_matrix(np.array([[0, 1, 0], [1, 0, 1], [0, 1, 0]], dtype=float))
    L = normalized_laplacian(A)
    assert L.shape == (3, 3)
    vals, _ = smallest_eigenpairs(L, k=2)
    assert abs(vals[0]) < 1e-6

def test_disconnected_has_two_zeros():
    A = sparse.csr_matrix(np.array([[0, 1, 0, 0], [1, 0, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0]], dtype=float))
    L = normalized_laplacian(A)
    vals, _ = smallest_eigenpairs(L, k=2)
    assert abs(vals[1]) < 1e-6
