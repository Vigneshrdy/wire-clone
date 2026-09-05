"""Drift detection. Produces *signals* only -- it never retrains or deploys.

Three metrics, each applied where it is actually valid:

* **PSI** (population stability index) for continuous features, binned on the
  reference distribution's quantiles. The standard operational thresholds are
  0.1 (watch) and 0.2 (act); the default here is 0.2.
* **KS** two-sample statistic for continuous features, as a distribution-shape
  check that does not depend on bin choice.
* **Jensen-Shannon divergence** for categorical and class distributions, where
  quantile binning is meaningless.

Using one metric for everything is the usual mistake: PSI on a binary feature is
noise, and KS on class counts is undefined.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np
from scipy import stats as scipy_stats

from ..config import Settings, get_settings
from ..metrics import DRIFT_EVENTS
from ..schemas import DriftEvent, DriftType

#: Laplace smoothing so an empty bin does not make PSI infinite.
EPSILON = 1e-6


def population_stability_index(
    reference: Sequence[float], current: Sequence[float], bins: int = 10
) -> float:
    """PSI between two continuous samples, binned on reference quantiles.

    Quantile bins (rather than equal-width) keep every reference bin populated,
    which is what makes the statistic stable for skewed network features such as
    byte counts.
    """
    if len(reference) < 2 or len(current) < 1:
        return 0.0
    quantiles = np.linspace(0, 100, bins + 1)
    edges = np.unique(np.percentile(reference, quantiles))
    if edges.size < 3:
        # Reference is (nearly) constant: PSI is not meaningful, report the
        # fraction of current values that fall outside the constant instead.
        constant = float(edges[0])
        outside = float(np.mean(np.asarray(current, dtype=float) != constant))
        return outside
    ref_hist, _ = np.histogram(reference, bins=edges)
    cur_hist, _ = np.histogram(current, bins=edges)
    ref_share = ref_hist / max(1, ref_hist.sum())
    cur_share = cur_hist / max(1, cur_hist.sum())
    psi = 0.0
    for r, c in zip(ref_share, cur_share):
        r_adj, c_adj = max(r, EPSILON), max(c, EPSILON)
        psi += (c_adj - r_adj) * math.log(c_adj / r_adj)
    return float(psi)


def ks_statistic(reference: Sequence[float], current: Sequence[float]) -> float:
    """Two-sample Kolmogorov-Smirnov D statistic (0 = identical)."""
    if len(reference) < 2 or len(current) < 2:
        return 0.0
    return float(scipy_stats.ks_2samp(reference, current).statistic)


def jensen_shannon_divergence(
    reference: Mapping[str, float], current: Mapping[str, float]
) -> float:
    """JS divergence in bits between two categorical distributions, in [0, 1]."""
    keys = sorted(set(reference) | set(current))
    if not keys:
        return 0.0
    ref = np.array([max(float(reference.get(k, 0.0)), 0.0) for k in keys])
    cur = np.array([max(float(current.get(k, 0.0)), 0.0) for k in keys])
    if ref.sum() <= 0 or cur.sum() <= 0:
        return 0.0
    p, q = ref / ref.sum(), cur / cur.sum()
    m = 0.5 * (p + q)

    def _kl(a: np.ndarray, b: np.ndarray) -> float:
        mask = a > 0
        return float(np.sum(a[mask] * np.log2(a[mask] / np.maximum(b[mask], EPSILON))))

    return max(0.0, min(1.0, 0.5 * _kl(p, m) + 0.5 * _kl(q, m)))


def is_discrete(values: Sequence[float], max_distinct: int = 4) -> bool:
    """Treat a feature with very few distinct values as categorical.

    Binary flags (``dns_is_txt``, ``*_baseline_warm``) are common in this feature
    set and PSI on them is meaningless.
    """
    return len(set(values)) <= max_distinct


@dataclass
class DriftMonitor:
    """Compares a reference window to a current window and emits DriftEvents."""

    settings: Settings | None = None

    def __post_init__(self) -> None:
        self.settings = self.settings or get_settings()
        self.config = self.settings.drift

    def _event(
        self, *, detector: str, model_version: str | None, feature: str | None,
        drift_type: DriftType, metric: str, score: float, threshold: float,
        window: str, reference_size: int, current_size: int, recommendation: str,
    ) -> DriftEvent:
        event = DriftEvent(
            detector=detector, model_version=model_version, feature=feature,
            drift_type=drift_type, metric=metric, score=score, threshold=threshold,
            window=window, reference_size=reference_size, current_size=current_size,
            recommendation=recommendation,
        )
        DRIFT_EVENTS.inc(detector=detector, drift_type=str(drift_type))
        return event

    def feature_drift(
        self,
        detector: str,
        reference: Mapping[str, Sequence[float]],
        current: Mapping[str, Sequence[float]],
        *,
        model_version: str | None = None,
        window: str = "unspecified",
    ) -> list[DriftEvent]:
        """Per-feature drift across two sets of feature samples.

        Returns only *breaching* features: a report listing 200 stable features is
        noise an analyst will stop reading.
        """
        events: list[DriftEvent] = []
        for feature, ref_values in reference.items():
            cur_values = current.get(feature)
            if cur_values is None:
                continue
            if len(ref_values) < self.config.min_samples or len(cur_values) < self.config.min_samples:
                continue
            if is_discrete(ref_values):
                ref_counts = _counts(ref_values)
                cur_counts = _counts(cur_values)
                score = jensen_shannon_divergence(ref_counts, cur_counts)
                if score >= self.config.js_threshold:
                    events.append(self._event(
                        detector=detector, model_version=model_version, feature=feature,
                        drift_type=DriftType.FEATURE_DISTRIBUTION, metric="jensen_shannon",
                        score=score, threshold=self.config.js_threshold, window=window,
                        reference_size=len(ref_values), current_size=len(cur_values),
                        recommendation="categorical feature distribution changed; review "
                                       "sensor configuration before retraining",
                    ))
                continue
            psi = population_stability_index(ref_values, cur_values, self.config.bins)
            if psi >= self.config.psi_threshold:
                events.append(self._event(
                    detector=detector, model_version=model_version, feature=feature,
                    drift_type=DriftType.FEATURE_DISTRIBUTION, metric="psi",
                    score=psi, threshold=self.config.psi_threshold, window=window,
                    reference_size=len(ref_values), current_size=len(cur_values),
                    recommendation="build a new training dataset covering the current "
                                   "distribution; do not promote without evaluation",
                ))
                continue
            ks = ks_statistic(ref_values, cur_values)
            if ks >= self.config.ks_threshold:
                events.append(self._event(
                    detector=detector, model_version=model_version, feature=feature,
                    drift_type=DriftType.FEATURE_DISTRIBUTION, metric="ks",
                    score=ks, threshold=self.config.ks_threshold, window=window,
                    reference_size=len(ref_values), current_size=len(cur_values),
                    recommendation="distribution shape changed without a PSI breach; "
                                   "monitor before acting",
                ))
        return events

    def score_drift(
        self,
        detector: str,
        reference: Sequence[float],
        current: Sequence[float],
        *,
        drift_type: DriftType = DriftType.CONFIDENCE_DISTRIBUTION,
        model_version: str | None = None,
        window: str = "unspecified",
    ) -> DriftEvent | None:
        """Drift in a model's own output distribution (confidence or prediction)."""
        if len(reference) < self.config.min_samples or len(current) < self.config.min_samples:
            return None
        psi = population_stability_index(reference, current, self.config.bins)
        if psi < self.config.psi_threshold:
            return None
        return self._event(
            detector=detector, model_version=model_version, feature=None,
            drift_type=drift_type, metric="psi", score=psi,
            threshold=self.config.psi_threshold, window=window,
            reference_size=len(reference), current_size=len(current),
            recommendation="model output distribution shifted; check for sensor "
                           "changes and review recent analyst feedback",
        )

    def class_distribution_drift(
        self,
        detector: str,
        reference: Mapping[str, float],
        current: Mapping[str, float],
        *,
        model_version: str | None = None,
        window: str = "unspecified",
    ) -> DriftEvent | None:
        score = jensen_shannon_divergence(reference, current)
        if score < self.config.js_threshold:
            return None
        return self._event(
            detector=detector, model_version=model_version, feature=None,
            drift_type=DriftType.CLASS_DISTRIBUTION, metric="jensen_shannon",
            score=score, threshold=self.config.js_threshold, window=window,
            reference_size=int(sum(reference.values())),
            current_size=int(sum(current.values())),
            recommendation="alert class mix changed; verify it reflects the "
                           "environment rather than a detector regression",
        )

    def label_performance_drift(
        self,
        detector: str,
        reference_precision: float,
        current_precision: float,
        *,
        sample_size: int,
        model_version: str | None = None,
        window: str = "unspecified",
        max_drop: float = 0.1,
    ) -> DriftEvent | None:
        """Precision decay measured from analyst feedback -- the ground-truth check.

        This is the signal that actually matters: feature drift may be harmless,
        but falling precision means analysts are being sent to the wrong places.
        """
        drop = reference_precision - current_precision
        if drop < max_drop or sample_size < 10:
            return None
        return self._event(
            detector=detector, model_version=model_version, feature=None,
            drift_type=DriftType.LABEL_PERFORMANCE, metric="precision_drop",
            score=drop, threshold=max_drop, window=window,
            reference_size=sample_size, current_size=sample_size,
            recommendation=f"precision fell from {reference_precision:.2f} to "
                           f"{current_precision:.2f}; build a dataset from recent "
                           "false positives and evaluate a challenger",
        )


def _counts(values: Iterable[float]) -> dict[str, float]:
    out: dict[str, float] = {}
    for value in values:
        key = f"{float(value):g}"
        out[key] = out.get(key, 0.0) + 1.0
    return out


def feature_matrix(rows: Iterable[Mapping[str, float]]) -> dict[str, list[float]]:
    """Transpose ``[{feature: value}]`` into ``{feature: [values]}``."""
    out: dict[str, list[float]] = {}
    for row in rows:
        for key, value in row.items():
            out.setdefault(key, []).append(float(value))
    return out
