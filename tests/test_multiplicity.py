import numpy as np

from cryptoh.spectral.multiplicity import detect, multiplicity


def test_isolated_cluster_fires():
    assert detect(1, 4)["fired"] is True

def test_stable_no_fire():
    assert detect(1, 1)["fired"] is False

def test_multiplicity_counts_near_zero():
    assert multiplicity(np.array([0.0, 0.005, 0.5, 1.2])) == 2
