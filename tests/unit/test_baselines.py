"""Baselines: cold start must be explicit, and a spike must not mask itself."""

from __future__ import annotations

import pytest

from sih_ntd.baselines import BaselineStore
from sih_ntd.schemas import EntityKind


def test_cold_baseline_returns_none_not_an_anomaly():
    """'Never seen this host' must never read as 'this host is anomalous'."""
    store = BaselineStore(alpha=0.2, min_observations=5)
    assert store.deviation(EntityKind.HOST, "10.0.0.1", "rate", 10_000.0) is None


def test_baseline_warms_after_min_observations():
    store = BaselineStore(alpha=0.2, min_observations=5)
    for _ in range(5):
        store.update(EntityKind.HOST, "10.0.0.1", "rate", 100.0)
    deviation = store.deviation(EntityKind.HOST, "10.0.0.1", "rate", 100.0)
    assert deviation is not None and deviation.observations == 5


def test_first_observation_seeds_the_mean():
    """Seeding from 0.0 would make the first real sample look like a huge jump."""
    store = BaselineStore(alpha=0.2, min_observations=1)
    baseline = store.update(EntityKind.HOST, "h", "m", 500.0)
    assert baseline.mean == 500.0 and baseline.variance == 0.0


def test_observe_compares_before_folding_in():
    store = BaselineStore(alpha=0.3, min_observations=3)
    for value in (10.0, 11.0, 9.0, 10.0):
        store.observe(EntityKind.HOST, "h", "m", value)
    deviation = store.observe(EntityKind.HOST, "h", "m", 1000.0)
    assert deviation is not None
    assert deviation.observed == 1000.0
    assert deviation.baseline_mean < 20.0, "the spike must not be inside its own baseline"


def test_destination_rarity_decays_with_familiarity():
    store = BaselineStore()
    assert store.destination_rarity("a", "unseen") == 1.0
    for _ in range(20):
        store.note_destination("a", "known")
    assert store.destination_rarity("a", "known") == 0.0


def test_percentiles_available_from_the_reservoir():
    store = BaselineStore(alpha=0.1, min_observations=5)
    for value in range(100):
        store.update(EntityKind.HOST, "h", "m", float(value))
    baseline = store.get(EntityKind.HOST, "h", "m")
    assert 80.0 <= baseline.percentile(0.95) <= 99.0


def test_snapshot_round_trip_preserves_state():
    store = BaselineStore(alpha=0.2, min_observations=2)
    for value in (5.0, 7.0, 6.0):
        store.update(EntityKind.HOST, "h", "m", value)
    snapshot = store.snapshot()
    restored = BaselineStore(alpha=0.2, min_observations=2)
    assert restored.restore(snapshot) == len(snapshot)
    assert restored.get(EntityKind.HOST, "h", "m").mean == pytest.approx(
        store.get(EntityKind.HOST, "h", "m").mean
    )


def test_store_is_bounded():
    store = BaselineStore(capacity=10)
    for i in range(50):
        store.update(EntityKind.HOST, f"host-{i}", "m", 1.0)
    assert len(store) <= 10
