"""Reusable time-window primitives.

Every rate, cardinality and inter-arrival statistic in the system is built from
the four classes here. Detectors never implement their own windowing -- that is
how two detectors end up disagreeing about what "flows per second" means.

Conventions
-----------
* Time is float epoch seconds (as delivered by Zeek/NetFlow), monotonic within a
  replay because events are processed in timestamp order.
* :meth:`SlidingWindow.rate` divides by the *window size*, not by the observed
  span. Dividing by the observed span makes a single event look like a 1000/s
  flood during the first millisecond of a window. Callers that need to know
  whether a window is warm read :attr:`SlidingWindow.coverage`.
* ``expire`` is explicit and idempotent: state only advances when an event or a
  tick tells it to, which keeps replay deterministic and unit tests free of
  wall-clock dependence.
"""

from __future__ import annotations

import math
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from typing import Hashable, Iterator


def window_suffix(size_seconds: float) -> str:
    """``1.0 -> '1s'``, ``0.5 -> '0.5s'``. Used to build feature names."""
    if size_seconds == int(size_seconds):
        return f"{int(size_seconds)}s"
    return f"{size_seconds:g}s"


@dataclass
class SlidingWindow:
    """Time-bounded sum/count of numeric observations."""

    size_seconds: float
    _entries: deque[tuple[float, float]] = field(default_factory=deque, repr=False)
    _total: float = 0.0
    _first_seen: float | None = None

    def add(self, ts: float, value: float = 1.0) -> None:
        self._entries.append((ts, value))
        self._total += value
        if self._first_seen is None:
            self._first_seen = ts

    def expire(self, now: float) -> None:
        cutoff = now - self.size_seconds
        entries = self._entries
        while entries and entries[0][0] <= cutoff:
            self._total -= entries.popleft()[1]
        if not entries:
            self._total = 0.0

    @property
    def count(self) -> int:
        return len(self._entries)

    @property
    def total(self) -> float:
        # Floating-point subtraction in expire() can leave a tiny negative residue.
        return max(0.0, self._total)

    @property
    def mean(self) -> float:
        return self.total / self.count if self._entries else 0.0

    def rate(self) -> float:
        return self.total / self.size_seconds

    def count_rate(self) -> float:
        return self.count / self.size_seconds

    def coverage(self, now: float) -> float:
        """Fraction of the window for which data actually exists, in [0, 1].

        A detector should not call a 300s baseline "exceeded" when only 4s of the
        window has been observed; this is the cold-start signal.
        """
        if self._first_seen is None:
            return 0.0
        return min(1.0, max(0.0, (now - self._first_seen) / self.size_seconds))

    def values(self) -> list[float]:
        return [v for _, v in self._entries]

    def timestamps(self) -> list[float]:
        return [t for t, _ in self._entries]


@dataclass
class UniqueTracker:
    """Time-bounded multiset: cardinality plus the counts needed for entropy."""

    size_seconds: float
    _entries: deque[tuple[float, Hashable]] = field(default_factory=deque, repr=False)
    _counts: Counter = field(default_factory=Counter, repr=False)

    def add(self, ts: float, key: Hashable) -> None:
        self._entries.append((ts, key))
        self._counts[key] += 1

    def expire(self, now: float) -> None:
        cutoff = now - self.size_seconds
        entries = self._entries
        counts = self._counts
        while entries and entries[0][0] <= cutoff:
            _, key = entries.popleft()
            remaining = counts[key] - 1
            if remaining <= 0:
                del counts[key]
            else:
                counts[key] = remaining

    @property
    def cardinality(self) -> int:
        return len(self._counts)

    @property
    def observations(self) -> int:
        return len(self._entries)

    def counts(self) -> dict[Hashable, int]:
        return dict(self._counts)

    def top_share(self) -> float:
        """Share of observations held by the most frequent key -- concentration.

        Near 1.0 means traffic is aimed at a single target (volumetric DDoS);
        near 0 means it is spread out (scanning).
        """
        if not self._entries:
            return 0.0
        return self._counts.most_common(1)[0][1] / len(self._entries)

    def seen(self, key: Hashable) -> bool:
        return key in self._counts


@dataclass
class IntervalTracker:
    """Recent arrival times for one entity, kept for inter-arrival statistics.

    Bounded by count rather than by time because periodicity needs a fixed number
    of intervals to be meaningful, and a 24-hour beacon would fall out of any
    reasonable time window.
    """

    maxlen: int = 64
    _times: deque[float] = field(default_factory=deque, repr=False)
    _last: float | None = None

    def __post_init__(self) -> None:
        self._times = deque(maxlen=self.maxlen)

    def add(self, ts: float) -> None:
        # Ignore duplicate timestamps: a zero interval is an artefact of
        # second-granularity sources, not evidence of a 0s beacon.
        if self._last is not None and ts <= self._last:
            return
        self._times.append(ts)
        self._last = ts

    def intervals(self) -> list[float]:
        times = list(self._times)
        return [b - a for a, b in zip(times, times[1:])]

    @property
    def count(self) -> int:
        return len(self._times)

    @property
    def last(self) -> float | None:
        return self._last

    @property
    def first(self) -> float | None:
        return self._times[0] if self._times else None


class LruStateMap(OrderedDict):
    """Bounded entity-state map. Oldest-touched entity is dropped when full.

    Unbounded per-IP state is the standard way a passive sensor dies under a
    spoofed-source flood, which is exactly the traffic this system must survive.
    """

    def __init__(self, capacity: int) -> None:
        super().__init__()
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self.evictions = 0

    def touch(self, key, factory):
        try:
            value = self[key]
            self.move_to_end(key)
            return value
        except KeyError:
            value = factory()
            self[key] = value
            if len(self) > self.capacity:
                self.popitem(last=False)
                self.evictions += 1
            return value


def quantile(sorted_values: list[float], q: float) -> float:
    """Linear-interpolation quantile over an already-sorted list."""
    if not sorted_values:
        return math.nan
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = q * (len(sorted_values) - 1)
    low = int(math.floor(pos))
    high = min(low + 1, len(sorted_values) - 1)
    frac = pos - low
    return sorted_values[low] * (1 - frac) + sorted_values[high] * frac


def iter_windows(sizes: list[float]) -> Iterator[tuple[float, str]]:
    for size in sizes:
        yield size, window_suffix(size)
