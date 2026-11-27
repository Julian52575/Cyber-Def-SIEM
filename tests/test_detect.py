from my_siem.detect import RateDetector


def test_alerts_when_threshold_reached_within_window() -> None:
    d = RateDetector(threshold=3, window=10)
    assert [d.hit("1.2.3.4", t) for t in (0, 1, 2)] == [False, False, True]


def test_old_hits_fall_out_of_window() -> None:
    d = RateDetector(threshold=3, window=10)
    assert [d.hit("1.2.3.4", t) for t in (0, 1, 11, 12)] == [False] * 4


def test_keys_are_counted_separately() -> None:
    d = RateDetector(threshold=2, window=10)
    assert not d.hit("a", 0)
    assert not d.hit("b", 1)
    assert d.hit("a", 2)


def test_alerts_once_per_burst() -> None:
    d = RateDetector(threshold=2, window=10)
    assert [d.hit("a", t) for t in (0, 1, 2, 3)] == [False, True, False, True]
