# Spectral Math

The harness uses the **normalized graph Laplacian** (Chung, 1997):

```
L_norm = I - D^{-1/2} A_sym D^{-1/2}
```

where `A_sym = (A + A^T) / 2` is the symmetric adjacency matrix and `D` is the degree matrix.

Computed via `scipy.sparse.csgraph.laplacian(A_sym, normed=True)`.

Eigenvalues are bounded to `[0, 2]`. The three anomaly signals:

1. **Fiedler vector shift** — `λ_2` drop > 20% from baseline.
2. **Zero-eigenvalue multiplicity spike** — number of connected components increases.
3. **Spectral clustering outlier** — nodes in the eigenvector embedding farther than `μ + 3σ` from the centroid.

Detection requires at least 2 of 3 signals (2-of-3 rule).
