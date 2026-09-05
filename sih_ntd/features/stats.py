"""Pure statistics used by the feature engine and by offline training.

Every function here is stateless and deterministic. That matters for two
reasons: the same code path produces training rows and inference rows (no
train/serve skew), and unit tests can assert exact values without fixtures.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Hashable, Iterable, Mapping, Sequence

VOWELS = frozenset("aeiou")
HEX_CHARS = frozenset("0123456789abcdef")


def shannon_entropy(counts: Mapping[Hashable, int] | Iterable[int]) -> float:
    """Shannon entropy in bits of an empirical distribution."""
    values = list(counts.values()) if isinstance(counts, Mapping) else list(counts)
    total = sum(values)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for n in values:
        if n <= 0:
            continue
        p = n / total
        entropy -= p * math.log2(p)
    return entropy


def normalised_entropy(counts: Mapping[Hashable, int]) -> float:
    """Entropy divided by the maximum possible for this number of categories.

    Scale-free, so a threshold means the same thing for 10 sources and 10 000.
    Returns 0.0 for a single category (no uncertainty).
    """
    k = len([v for v in counts.values() if v > 0])
    if k <= 1:
        return 0.0
    return shannon_entropy(counts) / math.log2(k)


def char_entropy(text: str) -> float:
    """Per-character Shannon entropy in bits -- the classic DGA/tunnel signal."""
    if not text:
        return 0.0
    return shannon_entropy(Counter(text))


def mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def stdev(values: Sequence[float]) -> float:
    """Population standard deviation (n, not n-1): windows are the population."""
    if len(values) < 2:
        return 0.0
    mu = mean(values)
    return math.sqrt(sum((v - mu) ** 2 for v in values) / len(values))


def coefficient_of_variation(values: Sequence[float]) -> float:
    """stdev / mean. Scale-free dispersion; the core of the beaconing signal."""
    mu = mean(values)
    if mu <= 0:
        return 0.0
    return stdev(values) / mu


def periodicity_score(intervals: Sequence[float], min_intervals: int = 6) -> float:
    """Score in [0, 1] for "these arrivals look like a fixed-period beacon".

    Deliberately simple and auditable rather than an FFT:

        regularity = 1 - min(1, CV(intervals))
        support    = min(1, len(intervals) / min_intervals)
        score      = regularity * support

    ``regularity`` is 1 for a perfect metronome and decays as jitter grows.
    ``support`` prevents three lucky connections from scoring 1.0 -- with fewer
    than ``min_intervals`` samples the score is scaled down proportionally, so
    the score answers "how much periodic evidence is there", not just "how even
    were the gaps".

    A high score is NOT proof of C2. Software updaters, NTP, and monitoring
    agents are all excellent beacons; the C2 detector requires corroborating
    evidence (rare destination, stable payload size) before it fires.
    """
    if not intervals:
        return 0.0
    regularity = max(0.0, 1.0 - min(1.0, coefficient_of_variation(intervals)))
    support = min(1.0, len(intervals) / float(min_intervals))
    return regularity * support


def burstiness(intervals: Sequence[float]) -> float:
    """Goh-Barabasi burstiness B = (sd - mean) / (sd + mean), in [-1, 1].

    -1 == perfectly periodic, 0 == Poisson, +1 == extremely bursty.
    """
    if len(intervals) < 2:
        return 0.0
    sd = stdev(intervals)
    mu = mean(intervals)
    if sd + mu == 0:
        return 0.0
    return (sd - mu) / (sd + mu)


def zscore(value: float, baseline_mean: float, baseline_stdev: float) -> float:
    """Deviation in standard deviations, with a floor so a flat baseline cannot
    divide by zero and produce an infinite anomaly."""
    if baseline_stdev <= 1e-9:
        # A perfectly flat baseline plus any change is suspicious but not
        # infinitely so; fall back to a relative measure.
        if baseline_mean <= 1e-9:
            return 0.0
        return (value - baseline_mean) / max(1e-9, abs(baseline_mean))
    return (value - baseline_mean) / baseline_stdev


def ratio(numerator: float, denominator: float, cap: float = 1e6) -> float:
    """Bounded ratio. Returns ``cap`` when the denominator is zero and the
    numerator is not, which keeps "infinite amplification" finite and loggable."""
    if denominator > 0:
        return min(cap, numerator / denominator)
    return cap if numerator > 0 else 0.0


def normalise_exceedance(observed: float, threshold: float, saturation: float = 4.0) -> float:
    """Map "how far past a threshold" onto [0, 1] for rule-based confidence.

    ``observed == threshold`` -> 0.5, ``observed >= threshold * saturation`` -> 1.0.
    Linear in log-space so a 100x flood is not indistinguishable from a 4x one at
    the top of the scale. Documented because it is the single place where
    rule-based confidence numbers come from.
    """
    if threshold <= 0:
        return 1.0 if observed > 0 else 0.0
    if observed <= 0:
        return 0.0
    span = math.log(max(saturation, 1.0001))
    position = math.log(max(observed / threshold, 1e-9))
    if position <= 0:
        # Below threshold: scale 0 -> 0.5 linearly on the ratio itself.
        return max(0.0, 0.5 * (observed / threshold))
    return min(1.0, 0.5 + 0.5 * min(1.0, position / span))


# --- DNS lexical features -------------------------------------------------
# Used by BOTH the DGA detector at inference time and the DGA trainer offline.
# One definition, no skew. Names are stable: they are recorded in the model
# metadata as feature_names.


def registrable_suffix_length(labels: Sequence[str]) -> int:
    """Length of the last two labels ("example.com") -- the part a DGA does not
    control. Kept as a feature so the model does not learn the TLD instead of
    the randomness."""
    return sum(len(x) for x in labels[-2:])


def longest_consonant_run(text: str) -> int:
    best = current = 0
    for ch in text:
        if ch.isalpha() and ch not in VOWELS:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def digit_ratio(text: str) -> float:
    return sum(ch.isdigit() for ch in text) / len(text) if text else 0.0


def vowel_ratio(text: str) -> float:
    letters = [ch for ch in text if ch.isalpha()]
    return sum(ch in VOWELS for ch in letters) / len(letters) if letters else 0.0


def unique_char_ratio(text: str) -> float:
    return len(set(text)) / len(text) if text else 0.0


def hex_ratio(text: str) -> float:
    """Share of characters that are hex digits -- catches base16-encoded tunnels."""
    return sum(ch in HEX_CHARS for ch in text) / len(text) if text else 0.0


def dns_lexical_features(domain: str) -> dict[str, float]:
    """Lexical feature map for one already-validated DNS name.

    Deliberately excludes n-gram/dictionary scores: those need a reference
    corpus, and shipping a corpus that inference and training must agree on
    reintroduces the skew risk this module exists to avoid. Revisit only if
    measured recall demands it.
    """
    labels = [x for x in domain.split(".") if x]
    # The "interesting" part is everything left of the registrable suffix; for a
    # 2-label domain that is the second-level label itself.
    payload = "".join(labels[:-2]) if len(labels) > 2 else (labels[0] if labels else "")
    longest_label = max((len(x) for x in labels), default=0)
    return {
        "dns_domain_length": float(len(domain)),
        "dns_label_count": float(len(labels)),
        "dns_longest_label_length": float(longest_label),
        "dns_subdomain_depth": float(max(0, len(labels) - 2)),
        "dns_payload_length": float(len(payload)),
        "dns_suffix_length": float(registrable_suffix_length(labels)),
        "dns_char_entropy": char_entropy(payload or domain),
        "dns_digit_ratio": digit_ratio(payload or domain),
        "dns_vowel_ratio": vowel_ratio(payload or domain),
        "dns_unique_char_ratio": unique_char_ratio(payload or domain),
        "dns_hex_ratio": hex_ratio(payload or domain),
        "dns_longest_consonant_run": float(longest_consonant_run(payload or domain)),
        "dns_hyphen_count": float(domain.count("-")),
        "dns_digit_present": 1.0 if any(ch.isdigit() for ch in payload or domain) else 0.0,
    }


DNS_LEXICAL_FEATURES: tuple[str, ...] = tuple(dns_lexical_features("example.com").keys())
