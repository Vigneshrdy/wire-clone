"""Metrics: cardinality guard and exposition format."""

from __future__ import annotations

import pytest

from sih_ntd import metrics


@pytest.fixture(autouse=True)
def _reset():
    metrics.reset()
    yield
    metrics.reset()


def test_undeclared_labels_are_refused():
    """An IP address as a Prometheus label value is an unbounded time series."""
    with pytest.raises(ValueError, match="undeclared labels"):
        metrics.EVENTS_RECEIVED.inc(src_ip="10.0.0.1")


def test_counter_accumulates_per_label_set():
    metrics.EVENTS_RECEIVED.inc(2, source_type="SYNTHETIC")
    metrics.EVENTS_RECEIVED.inc(3, source_type="SYNTHETIC")
    metrics.EVENTS_RECEIVED.inc(1, source_type="ZEEK_LOG")
    assert metrics.EVENTS_RECEIVED.value(source_type="SYNTHETIC") == 5
    assert metrics.EVENTS_RECEIVED.value(source_type="ZEEK_LOG") == 1


def test_gauge_sets_rather_than_adds():
    metrics.STREAM_LAG.set(10, stream="network.normalized")
    metrics.STREAM_LAG.set(4, stream="network.normalized")
    assert metrics.STREAM_LAG.value(stream="network.normalized") == 4


def test_histogram_buckets_are_cumulative():
    for value in (0.0004, 0.002, 0.2, 30.0):
        metrics.FEATURE_LATENCY.observe(value)
    rendered = "\n".join(metrics.FEATURE_LATENCY.render())
    assert 'sih_feature_latency_seconds_bucket{le="+Inf"} 4' in rendered
    assert "sih_feature_latency_seconds_count 4" in rendered
    assert metrics.FEATURE_LATENCY.count() == 4


def test_exposition_format_has_help_and_type_lines():
    metrics.ALERTS_TOTAL.inc(threat_class="DDOS", severity="HIGH")
    output = metrics.render()
    assert "# HELP sih_alerts_total" in output
    assert "# TYPE sih_alerts_total counter" in output
    assert 'sih_alerts_total{threat_class="DDOS",severity="HIGH"} 1.0' in output
    assert output.endswith("\n")
