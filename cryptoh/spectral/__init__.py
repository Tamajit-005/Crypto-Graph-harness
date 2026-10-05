"""Spectral detection core: Laplacian, 3 signals, 2-of-3 rule, rolling baseline."""
from cryptoh.spectral.baseline import Baseline
from cryptoh.spectral.clustering import detect as clustering_detect
from cryptoh.spectral.clustering import outlier_nodes
from cryptoh.spectral.fiedler import DEFAULT_DELTA
from cryptoh.spectral.fiedler import detect as fiedler_detect
from cryptoh.spectral.laplacian import normalized_laplacian, smallest_eigenpairs, symmetrize
from cryptoh.spectral.multiplicity import detect as multiplicity_detect
from cryptoh.spectral.multiplicity import multiplicity
from cryptoh.spectral.rule import combine

__all__ = [
    "DEFAULT_DELTA",
    "Baseline",
    "clustering_detect",
    "combine",
    "fiedler_detect",
    "multiplicity",
    "multiplicity_detect",
    "normalized_laplacian",
    "outlier_nodes",
    "smallest_eigenpairs",
    "symmetrize",
]
