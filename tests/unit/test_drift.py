"""Drift metrics, and the rule that drift never triggers an action."""

from __future__ import annotations

import numpy as np
import pytest

from sih_ntd.ml.drift import (
    DriftMonitor,
    feature_matrix,
    is_discrete,
    jensen_shannon_divergence,
    ks_statistic,
    population_stability_index,
)
from sih_ntd.schemas import DriftType


@pytest.fixture
def samples():
    rng = np.random.default_rng(7)
    return (
        list(rng.normal(0, 1, 2000)),
        list(rng.normal(0, 1, 2000)),
        list(rng.normal(3, 1, 2000)),
    )


def test_psi_near_zero_for_same_distribution(samples):
    reference, same, shifted = samples
    assert population_stability_index(reference, same) < 0.05
    assert population_stability_index(reference, shifted) > 0.2


def test_psi_handles_a_constant_reference():
    """Quantile binning collapses; the fallback must not divide by zero or explode."""
    score = population_stability_index([5.0] * 100, [5.0] * 50 + [9.0] * 50)
    assert 0.0 <= score <= 1.0


def test_ks_statistic_bounds(samples):
    reference, same, shifted = samples
    assert ks_statistic(reference, same) < 0.05
    assert ks_statistic(reference, shifted) > 0.5
    assert ks_statistic([1.0], [2.0]) == 0.0


def test_jensen_shannon_is_bounded():
    assert jensen_shannon_divergence({"a": 5, "b": 5}, {"a": 5, "b": 5}) == 0.0
    assert 0.0 < jensen_shannon_divergence({"a": 10, "b": 1}, {"a": 1, "b": 10}) <= 1.0
    assert jensen_shannon_divergence({}, {}) == 0.0


def test_binary_features_are_treated_as_categorical():
    """PSI on a 0/1 flag is noise; JS is the right metric."""
    assert is_discrete([0.0, 1.0] * 50)
    assert not is_discrete(list(range(50)))


def test_feature_drift_reports_only_breaching_features(samples):
    reference, same, shifted = samples
    events = DriftMonitor().feature_drift(
        "dga", {"stable": reference, "moved": reference}, {"stable": same, "moved": shifted}
    )
    assert [e.feature for e in events] == ["moved"]
    assert events[0].drift_type is DriftType.FEATURE_DISTRIBUTION
    assert events[0].breached and events[0].recommendation


def test_feature_drift_needs_enough_samples(settings):
    small = [1.0] * 10
    assert DriftMonitor().feature_drift("dga", {"f": small}, {"f": small}) == []


def test_label_performance_drift_uses_analyst_ground_truth():
    monitor = DriftMonitor()
    assert monitor.label_performance_drift("dga", 0.95, 0.92, sample_size=100) is None
    event = monitor.label_performance_drift("dga", 0.95, 0.70, sample_size=100)
    assert event is not None and event.drift_type is DriftType.LABEL_PERFORMANCE
    assert "precision fell" in event.recommendation


def test_drift_event_carries_no_action_only_a_recommendation():
    event = DriftMonitor().label_performance_drift("dga", 0.99, 0.5, sample_size=50)
    assert event is not None
    assert not hasattr(event, "retrain")
    assert "evaluate" in event.recommendation


def test_feature_matrix_transposes_rows():
    matrix = feature_matrix([{"a": 1.0, "b": 2.0}, {"a": 3.0}])
    assert matrix == {"a": [1.0, 3.0], "b": [2.0]}
