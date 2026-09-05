"""Prometheus-compatible metrics without the dependency.

Roughly 120 lines of stdlib covers counters, gauges and histograms plus text
exposition, which is all `/metrics` needs here.

The important design constraint is cardinality: label *values* derived from
traffic (IP addresses, domains, JA4 hashes) would create unbounded time series
and eventually take down the scrape target. :func:`Counter.inc` therefore only
accepts label names declared up front, and callers never pass an address.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Iterable

_LOCK = threading.Lock()

# Latency buckets in seconds: sub-millisecond feature work up to multi-second
# stalls. Chosen once here so every histogram is comparable.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
)


class _Metric:
    def __init__(self, name: str, help_text: str, labels: Iterable[str] = ()) -> None:
        self.name = name
        self.help_text = help_text
        self.labels = tuple(labels)

    def _key(self, label_values: dict[str, str]) -> tuple[str, ...]:
        unknown = set(label_values) - set(self.labels)
        if unknown:
            raise ValueError(f"metric {self.name}: undeclared labels {sorted(unknown)}")
        return tuple(str(label_values.get(name, "")) for name in self.labels)


class Counter(_Metric):
    def __init__(self, name: str, help_text: str, labels: Iterable[str] = ()) -> None:
        super().__init__(name, help_text, labels)
        self._values: dict[tuple[str, ...], float] = defaultdict(float)

    def inc(self, amount: float = 1.0, **label_values: str) -> None:
        key = self._key(label_values)
        with _LOCK:
            self._values[key] += amount

    def value(self, **label_values: str) -> float:
        return self._values.get(self._key(label_values), 0.0)

    def samples(self) -> list[tuple[str, tuple[str, ...], float]]:
        return [(self.name, key, val) for key, val in sorted(self._values.items())]


class Gauge(Counter):
    def set(self, value: float, **label_values: str) -> None:
        key = self._key(label_values)
        with _LOCK:
            self._values[key] = float(value)


class Histogram(_Metric):
    def __init__(
        self,
        name: str,
        help_text: str,
        labels: Iterable[str] = (),
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ) -> None:
        super().__init__(name, help_text, labels)
        self.buckets = buckets
        self._counts: dict[tuple[str, ...], list[int]] = defaultdict(
            lambda: [0] * (len(buckets) + 1)
        )
        self._sums: dict[tuple[str, ...], float] = defaultdict(float)

    def observe(self, seconds: float, **label_values: str) -> None:
        key = self._key(label_values)
        with _LOCK:
            counts = self._counts[key]
            self._sums[key] += seconds
            for i, edge in enumerate(self.buckets):
                if seconds <= edge:
                    counts[i] += 1
                    break
            else:
                counts[-1] += 1

    def count(self, **label_values: str) -> int:
        return sum(self._counts.get(self._key(label_values), []))

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} histogram"]
        for key, counts in sorted(self._counts.items()):
            base = dict(zip(self.labels, key))
            cumulative = 0
            for i, edge in enumerate(self.buckets):
                cumulative += counts[i]
                lines.append(f"{self.name}_bucket{_fmt_labels({**base, 'le': str(edge)})} {cumulative}")
            total = cumulative + counts[-1]
            lines.append(f"{self.name}_bucket{_fmt_labels({**base, 'le': '+Inf'})} {total}")
            lines.append(f"{self.name}_sum{_fmt_labels(base)} {self._sums[key]}")
            lines.append(f"{self.name}_count{_fmt_labels(base)} {total}")
        return lines


def _fmt_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items() if v != "")
    return f"{{{inner}}}" if inner else ""


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


# --- registry -------------------------------------------------------------
# Deliberately module-level and explicit: the metric set is part of the
# observability contract in docs/, so it is declared in one readable block.

EVENTS_RECEIVED = Counter("sih_events_received_total", "Normalized events accepted", ["source_type"])
EVENTS_REJECTED = Counter("sih_events_rejected_total", "Events rejected by validation", ["reason"])
FEATURES_GENERATED = Counter("sih_features_generated_total", "Feature vectors emitted", ["window"])
DETECTOR_RESULTS = Counter("sih_detector_results_total", "Detector verdicts", ["detector", "fired"])
DETECTOR_ERRORS = Counter("sih_detector_errors_total", "Detector exceptions caught", ["detector"])
ALERTS_TOTAL = Counter("sih_alerts_total", "Alerts emitted", ["threat_class", "severity"])
ALERTS_SUPPRESSED = Counter("sih_alerts_suppressed_total", "Alerts suppressed as duplicates", ["threat_class"])
DRIFT_EVENTS = Counter("sih_drift_events_total", "Drift signals raised", ["detector", "drift_type"])
STREAM_MESSAGES = Counter("sih_stream_messages_total", "Stream messages handled", ["stream", "outcome"])
DLQ_MESSAGES = Counter("sih_dlq_messages_total", "Messages routed to a dead-letter stream", ["stream"])
FEEDBACK_TOTAL = Counter("sih_feedback_total", "Analyst feedback recorded", ["label"])

STREAM_LAG = Gauge("sih_stream_lag_messages", "Pending (unacked) messages per stream", ["stream"])
TRACKED_ENTITIES = Gauge("sih_tracked_entities", "Entities held in feature-engine state", ["kind"])
DETECTOR_STATE = Gauge("sih_detector_state", "1 when a detector is READY", ["detector"])
MODEL_INFO = Gauge("sih_model_info", "1 per loaded champion model", ["detector", "model_version"])

FEATURE_LATENCY = Histogram("sih_feature_latency_seconds", "Feature generation latency")
INFERENCE_LATENCY = Histogram("sih_inference_latency_seconds", "Detector inference latency", ["detector"])
FUSION_LATENCY = Histogram("sih_fusion_latency_seconds", "Fusion latency")
PIPELINE_LATENCY = Histogram("sih_pipeline_latency_seconds", "Event ingest to alert latency")

_COUNTERS: tuple[Counter, ...] = (
    EVENTS_RECEIVED, EVENTS_REJECTED, FEATURES_GENERATED, DETECTOR_RESULTS,
    DETECTOR_ERRORS, ALERTS_TOTAL, ALERTS_SUPPRESSED, DRIFT_EVENTS,
    STREAM_MESSAGES, DLQ_MESSAGES, FEEDBACK_TOTAL,
)
_GAUGES: tuple[Gauge, ...] = (STREAM_LAG, TRACKED_ENTITIES, DETECTOR_STATE, MODEL_INFO)
_HISTOGRAMS: tuple[Histogram, ...] = (
    FEATURE_LATENCY, INFERENCE_LATENCY, FUSION_LATENCY, PIPELINE_LATENCY,
)


def render() -> str:
    """Prometheus text exposition format (version 0.0.4)."""
    lines: list[str] = []
    for metric, kind in [(c, "counter") for c in _COUNTERS] + [(g, "gauge") for g in _GAUGES]:
        lines.append(f"# HELP {metric.name} {metric.help_text}")
        lines.append(f"# TYPE {metric.name} {kind}")
        for name, key, value in metric.samples():
            lines.append(f"{name}{_fmt_labels(dict(zip(metric.labels, key)))} {value}")
    for hist in _HISTOGRAMS:
        lines.extend(hist.render())
    return "\n".join(lines) + "\n"


def reset() -> None:
    """Test helper: clear all series."""
    with _LOCK:
        for metric in (*_COUNTERS, *_GAUGES):
            metric._values.clear()
        for hist in _HISTOGRAMS:
            hist._counts.clear()
            hist._sums.clear()
