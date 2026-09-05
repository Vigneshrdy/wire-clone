"""Windowing primitives: expiry boundaries, rates, cardinality, LRU bounds."""

from __future__ import annotations

import pytest

from sih_ntd.windows import (
    IntervalTracker,
    LruStateMap,
    SlidingWindow,
    UniqueTracker,
    quantile,
    window_suffix,
)


def test_rate_is_per_window_not_per_observed_span():
    """Dividing by observed span makes one event look like a flood; it must not."""
    window = SlidingWindow(1.0)
    window.add(100.0)
    assert window.rate() == 1.0
    assert window.coverage(100.001) < 0.01, "coverage exposes the cold window instead"


def test_entries_expire_exactly_at_the_boundary():
    window = SlidingWindow(5.0)
    for ts in (100.0, 101.0, 102.0):
        window.add(ts, 10.0)
    window.expire(105.0)  # cutoff == 100.0, entries at <= cutoff drop
    assert window.count == 2
    assert window.total == 20.0
    window.expire(110.0)
    assert window.count == 0 and window.total == 0.0


def test_expire_is_idempotent():
    window = SlidingWindow(2.0)
    window.add(10.0)
    window.expire(20.0)
    window.expire(20.0)
    assert window.count == 0


def test_totals_never_go_negative_through_float_drift():
    window = SlidingWindow(1.0)
    for i in range(1000):
        window.add(i * 0.0001, 0.1)
    window.expire(10.0)
    assert window.total >= 0.0


def test_unique_tracker_cardinality_and_concentration():
    tracker = UniqueTracker(10.0)
    for i in range(10):
        tracker.add(100.0 + i, "target" if i < 8 else f"other{i}")
    assert tracker.cardinality == 3
    assert tracker.top_share() == pytest.approx(0.8)


def test_unique_tracker_forgets_expired_keys():
    tracker = UniqueTracker(5.0)
    tracker.add(100.0, "a")
    tracker.add(101.0, "b")
    tracker.expire(107.0)
    assert tracker.cardinality == 0 and not tracker.seen("a")


def test_interval_tracker_ignores_duplicate_timestamps():
    """Second-granularity sources repeat timestamps; a 0s interval is an artefact."""
    tracker = IntervalTracker(10)
    for ts in (0.0, 0.0, 30.0, 30.0, 60.0):
        tracker.add(ts)
    assert tracker.intervals() == [30.0, 30.0]


def test_interval_tracker_is_bounded():
    tracker = IntervalTracker(4)
    for i in range(100):
        tracker.add(float(i))
    assert tracker.count == 4


def test_lru_state_map_evicts_least_recently_touched():
    lru = LruStateMap(2)
    lru.touch("a", dict)
    lru.touch("b", dict)
    lru.touch("a", dict)          # refresh a
    lru.touch("c", dict)          # evicts b
    assert set(lru.keys()) == {"a", "c"}
    assert lru.evictions == 1


def test_lru_capacity_must_be_positive():
    with pytest.raises(ValueError):
        LruStateMap(0)


@pytest.mark.parametrize(
    ("values", "q", "expected"),
    [([1, 2, 3, 4], 0.5, 2.5), ([5], 0.9, 5.0), ([1, 2, 3, 4, 5], 0.0, 1.0)],
)
def test_quantile_interpolates(values, q, expected):
    assert quantile(values, q) == pytest.approx(expected)


def test_window_suffix_formats_names():
    assert window_suffix(1.0) == "1s" and window_suffix(0.5) == "0.5s"
