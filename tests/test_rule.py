from cryptoh.spectral.rule import combine


def test_two_of_three_fires():
    assert combine([True, True, False])["anomaly"] is True

def test_single_signal_no_fire():
    assert combine([True, False, False])["anomaly"] is False

def test_zero_signals():
    r = combine([False, False, False])
    assert r["anomaly"] is False and r["votes"] == 0
