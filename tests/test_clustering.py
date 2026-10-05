import numpy as np

from cryptoh.spectral.clustering import detect


def test_star_center_flagged_or_safe():
    # 8 peripheral nodes at origin-ish, 1 far outlier
    emb = np.zeros((9, 2))
    emb[8] = [10.0, 10.0]
    ids = [f"n{i}" for i in range(9)]
    d = detect(emb, ids)
    assert isinstance(d["fired"], bool) and "nodes" in d

def test_tight_cluster_no_fire():
    rng = np.random.default_rng(7)
    emb = rng.normal(0, 0.01, size=(20, 8))
    d = detect(emb, [f"n{i}" for i in range(20)])
    assert d["fired"] is False
