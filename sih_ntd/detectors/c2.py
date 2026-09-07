"""Botnet C2 beaconing detection on source->destination pairs.

Periodicity alone is worthless as evidence: NTP, software updaters, monitoring
agents and heartbeat probes are all near-perfect beacons. This detector therefore
requires a regular interval *plus* at least ``MIN_CORROBORATION`` independent
supporting signals:

* the destination is rare for this source
* payload size is unusually stable across connections (fixed-size check-ins)
* connection duration is unusually stable
* the destination is external to the monitored network
* the flows are short (check-in, not a session)

The periodicity score itself is documented in
:func:`sih_ntd.features.stats.periodicity_score` -- regularity scaled by how many
intervals were actually observed, so three lucky connections cannot score 1.0.
"""

from __future__ import annotations

from ..schemas import (
    ConfidenceBasis,
    DetectorInput,
    DetectorResult,
    EntityKind,
    Severity,
    Technique,
    ThreatClass,
)
from .base import Detector

MIN_CORROBORATION = 2
#: Beacon intervals below this are chatty application traffic, not C2. Real
#: implants sleep in tens of seconds to minutes (Cobalt Strike defaults to 60s);
#: sub-5s "regular" traffic is polling, keepalives and media streams, and treating
#: it as a beacon produced a false positive on ordinary 1s-interval uploads during
#: fixture testing.
MIN_PLAUSIBLE_INTERVAL = 5.0
#: Above this, too few samples fit in the tracker to judge regularity here.
MAX_PLAUSIBLE_INTERVAL = 3600.0


class C2BeaconDetector(Detector):
    name = "c2_beacon"
    version = "1.0.0"
    threat_class = ThreatClass.C2_BEACON
    technique = Technique.STATISTICAL
    confidence_basis = ConfidenceBasis.NORMALISED_ANOMALY
    entity_kinds = (EntityKind.PAIR,)

    def evaluate(self, payload: DetectorInput) -> DetectorResult | None:
        f = payload.features
        t = self.thresholds

        intervals = f.get("interarrival_count")
        if intervals < t.c2_min_intervals:
            return None

        mean_interval = f.get("interarrival_mean")
        if not (MIN_PLAUSIBLE_INTERVAL <= mean_interval <= MAX_PLAUSIBLE_INTERVAL):
            return None

        cv = f.get("interarrival_cv")
        periodicity = f.get("periodicity_score")
        if cv > t.c2_max_cv or periodicity < t.c2_periodicity_score:
            return None

        stdev = f.get("interarrival_stdev")
        if stdev > t.c2_max_jitter_seconds:
            # Regular in relative terms but hours of absolute jitter -- not a beacon.
            return None

        byte_cv = f.get("byte_stability_cv")
        duration_cv = f.get("duration_stability_cv")
        rarity = f.get("destination_rarity")
        external = f.get("is_internal_destination") == 0.0

        corroboration: list[str] = []
        if rarity >= 0.5:
            corroboration.append("RARE_DESTINATION")
        if 0.0 <= byte_cv <= t.c2_byte_stability_cv:
            corroboration.append("STABLE_PAYLOAD_SIZE")
        if 0.0 <= duration_cv <= t.c2_byte_stability_cv:
            corroboration.append("STABLE_CONNECTION_DURATION")
        if external:
            corroboration.append("EXTERNAL_DESTINATION")
        if 0.0 < f.get("mean_duration_60s") <= 5.0:
            corroboration.append("SHORT_CHECKIN_FLOWS")

        if len(corroboration) < MIN_CORROBORATION:
            # Regular timing on its own is not reported: that is the updater case.
            return None

        # Confidence: periodicity supplies the base, corroboration the rest. Both
        # halves are bounded so a single signal cannot saturate the score.
        corroboration_weight = min(1.0, (len(corroboration) - 1) / 4.0)
        confidence = min(0.97, 0.45 * periodicity + 0.35 * corroboration_weight + 0.15)

        supporting = {
            "interarrival_mean": mean_interval,
            "interarrival_stdev": stdev,
            "interarrival_cv": cv,
            "interarrival_count": intervals,
            "periodicity_score": periodicity,
            "burstiness": f.get("burstiness"),
            "byte_stability_cv": byte_cv,
            "duration_stability_cv": duration_cv,
            "mean_flow_bytes": f.get("mean_flow_bytes"),
            "destination_rarity": rarity,
            "observed_span": f.get("observed_span"),
            "corroborating_signals": float(len(corroboration)),
            # Emitted so a reader (and the console) can see what the score was
            # measured against, not just the score.
            "periodicity_threshold": t.c2_periodicity_score,
            "cv_threshold": t.c2_max_cv,
        }
        return self.build_result(
            f,
            score=periodicity,
            confidence=confidence,
            severity=self._severity(periodicity, len(corroboration), rarity),
            reason_codes=["PERIODIC_INTERVALS", *corroboration],
            supporting=supporting,
        )

    def _severity(self, periodicity: float, corroboration: int, rarity: float) -> Severity:
        """A confirmed beacon to a never-seen external host is a live intrusion."""
        if periodicity >= 0.9 and corroboration >= 4 and rarity >= 0.9:
            return Severity.HIGH
        if periodicity >= 0.85 and corroboration >= 3:
            return Severity.MEDIUM
        return Severity.LOW
