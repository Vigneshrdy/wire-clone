"""Behavioural baselines per entity.

An EWMA of mean and variance plus a bounded reservoir for quantiles, keyed by
``(entity_kind, entity_id, metric)``. EWMA is chosen over a fixed rolling window
because it needs O(1) state per series and adapts to slow legitimate change
(a host that genuinely gets busier) without holding history for every IP.

Cold start is explicit and non-negotiable: :attr:`Baseline.warm` is False until
``min_observations`` samples exist, and :meth:`BaselineStore.deviation` returns
``None`` for a cold series. A detector that treats "no baseline" as "anomaly"
alerts on every host it has never seen, which is every host at startup.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable

from .config import get_settings
from .schemas import EntityKind
from .windows import LruStateMap, quantile

# Reservoir for percentile estimates. 256 samples gives a usable p95 at trivial
# cost; exact quantiles would need unbounded history per series.
RESERVOIR_SIZE = 256


@dataclass
class Baseline:
    """EWMA mean/variance plus a bounded sample reservoir for one metric."""

    alpha: float
    min_observations: int
    mean: float = 0.0
    variance: float = 0.0
    count: int = 0
    last_value: float = 0.0
    samples: list[float] = field(default_factory=list, repr=False)

    @property
    def warm(self) -> bool:
        return self.count >= self.min_observations

    @property
    def stdev(self) -> float:
        return math.sqrt(max(0.0, self.variance))

    def update(self, value: float) -> None:
        """Fold in one observation.

        The first sample seeds the mean directly; seeding from 0.0 would make the
        first real observation look like an enormous jump.
        """
        value = float(value)
        self.last_value = value
        if self.count == 0:
            self.mean = value
            self.variance = 0.0
        else:
            delta = value - self.mean
            self.mean += self.alpha * delta
            # EWMA of squared deviation (West's incremental form).
            self.variance = (1 - self.alpha) * (self.variance + self.alpha * delta * delta)
        self.count += 1
        if len(self.samples) < RESERVOIR_SIZE:
            self.samples.append(value)
        else:
            # Ring replacement keeps the reservoir recent rather than uniformly
            # random; recency is what a behavioural baseline wants.
            self.samples[self.count % RESERVOIR_SIZE] = value

    def zscore(self, value: float) -> float:
        if not self.warm:
            return 0.0
        if self.stdev <= 1e-9:
            if abs(self.mean) <= 1e-9:
                return 0.0
            return (value - self.mean) / max(1e-9, abs(self.mean))
        return (value - self.mean) / self.stdev

    def percentile(self, q: float) -> float:
        if not self.samples:
            return math.nan
        return quantile(sorted(self.samples), q)

    def to_dict(self) -> dict[str, float]:
        return {
            "mean": self.mean,
            "variance": self.variance,
            "count": float(self.count),
            "last_value": self.last_value,
        }


@dataclass
class Deviation:
    """Result of comparing an observation against a warm baseline."""

    metric: str
    observed: float
    baseline_mean: float
    baseline_stdev: float
    zscore: float
    p95: float
    observations: int

    def as_evidence(self, prefix: str = "") -> dict[str, float]:
        p = prefix or self.metric
        return {
            f"{p}_observed": self.observed,
            f"{p}_baseline_mean": self.baseline_mean,
            f"{p}_baseline_stdev": self.baseline_stdev,
            f"{p}_baseline_p95": self.p95,
            f"{p}_zscore": self.zscore,
            f"{p}_baseline_observations": float(self.observations),
        }


class BaselineStore:
    """Bounded collection of baselines, keyed by entity and metric."""

    def __init__(self, capacity: int | None = None, alpha: float | None = None,
                 min_observations: int | None = None) -> None:
        settings = get_settings()
        self.alpha = alpha if alpha is not None else settings.thresholds.baseline_ewma_alpha
        self.min_observations = (
            min_observations if min_observations is not None
            else settings.thresholds.baseline_min_observations
        )
        self._series: LruStateMap = LruStateMap(capacity or settings.windows.max_tracked_entities)

    @staticmethod
    def key(kind: EntityKind, entity_id: str, metric: str) -> tuple[str, str, str]:
        return (str(kind), entity_id, metric)

    def get(self, kind: EntityKind, entity_id: str, metric: str) -> Baseline:
        return self._series.touch(
            self.key(kind, entity_id, metric),
            lambda: Baseline(alpha=self.alpha, min_observations=self.min_observations),
        )

    def update(self, kind: EntityKind, entity_id: str, metric: str, value: float) -> Baseline:
        baseline = self.get(kind, entity_id, metric)
        baseline.update(value)
        return baseline

    def deviation(
        self, kind: EntityKind, entity_id: str, metric: str, value: float
    ) -> Deviation | None:
        """Compare ``value`` to the baseline, or return None if it is still cold."""
        baseline = self.get(kind, entity_id, metric)
        if not baseline.warm:
            return None
        return Deviation(
            metric=metric,
            observed=value,
            baseline_mean=baseline.mean,
            baseline_stdev=baseline.stdev,
            zscore=baseline.zscore(value),
            p95=baseline.percentile(0.95),
            observations=baseline.count,
        )

    def observe(
        self, kind: EntityKind, entity_id: str, metric: str, value: float
    ) -> Deviation | None:
        """Compare first, then fold in.

        Order matters: folding the observation in before comparing lets a large
        spike partially mask itself.
        """
        dev = self.deviation(kind, entity_id, metric, value)
        self.update(kind, entity_id, metric, value)
        return dev

    def seen_destination(self, source: str, destination: str) -> bool:
        """Whether this source has talked to this destination before.

        Implemented on top of the baseline map so destination rarity does not need
        a second bounded store. Returns False on a cold entry, which callers must
        treat as "unknown, not proven rare".
        """
        key = self.key(EntityKind.PAIR, f"{source}->{destination}", "seen")
        return key in self._series

    def note_destination(self, source: str, destination: str) -> None:
        self.update(EntityKind.PAIR, f"{source}->{destination}", "seen", 1.0)

    def destination_rarity(self, source: str, destination: str) -> float:
        """0.0 for a destination this source contacts routinely, 1.0 for a first
        contact. Derived from the pair's observation count, saturating at 20
        contacts so a long-lived pair does not keep getting rarer-looking."""
        baseline = self.get(EntityKind.PAIR, f"{source}->{destination}", "seen")
        if baseline.count == 0:
            return 1.0
        return max(0.0, 1.0 - min(1.0, baseline.count / 20.0))

    def __len__(self) -> int:
        return len(self._series)

    def snapshot(self) -> dict[str, dict[str, float]]:
        """Serialisable state, for persisting baselines across restarts."""
        return {"|".join(k): v.to_dict() for k, v in self._series.items()}

    def restore(self, snapshot: dict[str, dict[str, float]]) -> int:
        restored = 0
        for flat_key, values in snapshot.items():
            parts = flat_key.split("|")
            if len(parts) != 3:
                continue
            baseline = self._series.touch(
                tuple(parts),
                lambda: Baseline(alpha=self.alpha, min_observations=self.min_observations),
            )
            baseline.mean = float(values.get("mean", 0.0))
            baseline.variance = float(values.get("variance", 0.0))
            baseline.count = int(values.get("count", 0))
            baseline.last_value = float(values.get("last_value", 0.0))
            restored += 1
        return restored

    def metrics_for(self, kind: EntityKind, entity_id: str) -> Iterable[str]:
        prefix = (str(kind), entity_id)
        return [k[2] for k in self._series if k[:2] == prefix]
