"""Data-exfiltration detection: statistical baseline deviation, not raw volume.

Absolute outbound volume is a terrible standalone signal -- backups, CI artefact
uploads, video calls and cloud sync all move large amounts of data outbound every
day. This detector therefore requires a volume trigger *plus* corroboration:

* the transfer is far outside this host's own historical behaviour (EWMA z-score
  or p95 exceedance), and/or
* the outbound/inbound byte ratio is extreme (upload, not conversation), and/or
* the destination is one this host rarely or never contacts.

Cold start is explicit: with no warm baseline the detector needs the absolute
volume trigger and at least one non-baseline corroborating signal, and it says
``BASELINE_COLD`` in the reason codes so nobody reads the alert as "abnormal for
this host" when that has not been established.
"""

from __future__ import annotations

from ..features import stats
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

#: Exfiltration is judged over the widest window: transfers take time.
WINDOW = "300s"
BASELINE_METRIC = "bytes_out_per_sec_60s"


class ExfiltrationDetector(Detector):
    name = "exfiltration"
    version = "1.0.0"
    threat_class = ThreatClass.EXFILTRATION
    technique = Technique.STATISTICAL
    confidence_basis = ConfidenceBasis.NORMALISED_ANOMALY
    entity_kinds = (EntityKind.HOST,)

    def evaluate(self, payload: DetectorInput) -> DetectorResult | None:
        f = payload.features
        t = self.thresholds

        # Only outbound traffic from inside the monitored estate is exfiltration.
        # Inbound bulk transfer is a download, not a leak.
        if f.get("is_internal_source") != 1.0 or f.get("is_internal_destination") == 1.0:
            return None

        outbound = f.get(f"bytes_out_total_{WINDOW}")
        if outbound < t.exfil_min_outbound_bytes:
            return None

        inbound = f.get(f"bytes_in_total_{WINDOW}")
        ratio = f.get(f"orig_resp_byte_ratio_{WINDOW}")
        rarity = f.get("destination_rarity")
        zscore = f.get(f"{BASELINE_METRIC}_zscore")
        baseline_warm = f.get(f"{BASELINE_METRIC}_baseline_warm") == 1.0
        baseline_p95 = f.get(f"{BASELINE_METRIC}_baseline_p95")
        observed_rate = f.get(BASELINE_METRIC)
        duration = f.get(f"mean_duration_{WINDOW}")

        corroboration: list[str] = []
        if ratio >= t.exfil_outbound_inbound_ratio:
            corroboration.append("OUTBOUND_DOMINATED_TRANSFER")
        if rarity >= t.exfil_destination_rarity:
            corroboration.append("RARE_DESTINATION")
        if baseline_warm and zscore >= t.exfil_baseline_zscore:
            corroboration.append("BASELINE_DEVIATION")
        if baseline_warm and baseline_p95 > 0 and observed_rate >= baseline_p95 * 2:
            corroboration.append("ABOVE_HISTORICAL_P95")
        if duration >= 60.0:
            corroboration.append("SUSTAINED_TRANSFER")
        if not baseline_warm:
            corroboration_needed = 1
        else:
            corroboration_needed = 1

        # Volume alone never fires: that is the design constraint for this detector.
        real_signals = [c for c in corroboration if c != "SUSTAINED_TRANSFER"]
        if len(real_signals) < corroboration_needed:
            return None

        reason_codes = ["HIGH_OUTBOUND_VOLUME", *corroboration]
        if not baseline_warm:
            reason_codes.append("BASELINE_COLD")

        volume_strength = stats.normalise_exceedance(outbound, float(t.exfil_min_outbound_bytes))
        ratio_strength = stats.normalise_exceedance(ratio, t.exfil_outbound_inbound_ratio)
        baseline_strength = min(1.0, zscore / (t.exfil_baseline_zscore * 2)) if baseline_warm else 0.0
        # Baseline evidence is the strongest of the three, so it is weighted highest.
        confidence = min(
            0.95,
            0.25 * volume_strength + 0.25 * ratio_strength + 0.35 * baseline_strength + 0.1 * rarity,
        )

        supporting = {
            f"bytes_out_total_{WINDOW}": outbound,
            f"bytes_in_total_{WINDOW}": inbound,
            f"orig_resp_byte_ratio_{WINDOW}": ratio,
            f"bytes_out_per_sec_{WINDOW}": f.get(f"bytes_out_per_sec_{WINDOW}"),
            "destination_rarity": rarity,
            f"{BASELINE_METRIC}": observed_rate,
            f"{BASELINE_METRIC}_zscore": zscore,
            f"{BASELINE_METRIC}_baseline_mean": f.get(f"{BASELINE_METRIC}_baseline_mean"),
            f"{BASELINE_METRIC}_baseline_p95": baseline_p95,
            f"{BASELINE_METRIC}_baseline_warm": 1.0 if baseline_warm else 0.0,
            f"mean_duration_{WINDOW}": duration,
            "volume_threshold": float(t.exfil_min_outbound_bytes),
            "ratio_threshold": t.exfil_outbound_inbound_ratio,
            "zscore_threshold": t.exfil_baseline_zscore,
        }
        return self.build_result(
            f,
            score=outbound / float(t.exfil_min_outbound_bytes),
            confidence=confidence,
            severity=self._severity(outbound, len(real_signals), baseline_warm),
            reason_codes=reason_codes,
            supporting=supporting,
        )

    def _severity(self, outbound: float, signals: int, baseline_warm: bool) -> Severity:
        """Impact scales with how much data left, not with how sure we are."""
        gigabyte = 1_000_000_000
        if outbound >= gigabyte and signals >= 2 and baseline_warm:
            return Severity.HIGH
        if outbound >= gigabyte or signals >= 2:
            return Severity.MEDIUM
        return Severity.LOW
