from cryptoh.spectral.fiedler import detect


def test_connectivity_drop_fires():
    assert detect(0.342, 0.087)["fired"] is True

def test_small_drift_no_fire():
    assert detect(0.342, 0.339)["fired"] is False

def test_no_baseline_no_fire():
    assert detect(0.0, 0.1)["fired"] is False
