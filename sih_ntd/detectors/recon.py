"""Reconnaissance / port-scan detection from the source host's perspective.

Purely deterministic and stateful. Scanning is defined by fan-out and failure,
both of which are counted exactly by the feature engine; a model would add
nothing except an unexplainable score, so there is none here (see
docs/DETECTORS.md).

Distinguishes:

* **vertical**   one or few hosts, many ports
* **horizontal** one or few ports, many hosts
* **distributed/sweep** many hosts *and* many ports

A high failed-connection ratio and very short flow durations separate a scan from
a busy legitimate client such as a proxy or a backup agent.
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

# Scans are judged over the 60s window: long enough to catch a slow scan, short
# enough that a legitimate burst of connections does not accumulate into one.
WINDOW = "60s"


class ReconDetector(Detector):
    name = "recon"
    version = "1.0.0"
    threat_class = ThreatClass.RECON
    technique = Technique.RULE
    confidence_basis = ConfidenceBasis.RULE_EVIDENCE
    entity_kinds = (EntityKind.HOST,)

    def evaluate(self, payload: DetectorInput) -> DetectorResult | None:
        f = payload.features
        t = self.thresholds

        flows = f.get(f"flow_count_{WINDOW}")
        if flows < t.recon_min_flows:
            return None

        unique_ports = f.get(f"unique_dst_ports_{WINDOW}")
        unique_hosts = f.get(f"unique_dst_ips_{WINDOW}")
        failed_ratio = f.get(f"failed_ratio_{WINDOW}")
        mean_duration = f.get(f"mean_duration_{WINDOW}")
        syn_ratio = f.get(f"syn_ratio_{WINDOW}")
        port_entropy = f.get(f"dst_port_entropy_{WINDOW}")

        vertical = unique_ports >= t.recon_unique_ports
        horizontal = unique_hosts >= t.recon_unique_hosts
        if not (vertical or horizontal):
            return None

        # A scanner's connections mostly fail or are never established. Without
        # this gate, any busy client with wide fan-out looks like a scan.
        if failed_ratio < t.recon_failed_ratio and syn_ratio < t.recon_failed_ratio:
            return None

        reason_codes: list[str] = []
        if vertical and horizontal:
            reason_codes.append("NETWORK_SWEEP")
            scan_kind = "sweep"
        elif vertical:
            reason_codes.append("VERTICAL_PORT_SCAN")
            scan_kind = "vertical"
        else:
            reason_codes.append("HORIZONTAL_HOST_SCAN")
            scan_kind = "horizontal"

        if failed_ratio >= t.recon_failed_ratio:
            reason_codes.append("HIGH_FAILED_CONNECTION_RATIO")
        if syn_ratio >= t.recon_failed_ratio:
            reason_codes.append("SYN_WITHOUT_ESTABLISH")
        if 0.0 < mean_duration <= t.recon_max_mean_duration:
            reason_codes.append("SHORT_LIVED_CONNECTIONS")

        port_strength = stats.normalise_exceedance(unique_ports, t.recon_unique_ports)
        host_strength = stats.normalise_exceedance(unique_hosts, t.recon_unique_hosts)
        strength = max(port_strength if vertical else 0.0, host_strength if horizontal else 0.0)
        # Failure ratio is the discriminating evidence, so it carries real weight.
        confidence = min(0.97, 0.45 + 0.35 * strength + 0.2 * max(failed_ratio, syn_ratio))

        supporting = {
            f"unique_dst_ports_{WINDOW}": unique_ports,
            f"unique_dst_ips_{WINDOW}": unique_hosts,
            f"failed_ratio_{WINDOW}": failed_ratio,
            f"syn_ratio_{WINDOW}": syn_ratio,
            f"mean_duration_{WINDOW}": mean_duration,
            f"dst_port_entropy_{WINDOW}": port_entropy,
            f"flow_count_{WINDOW}": flows,
            f"flows_per_sec_{WINDOW}": f.get(f"flows_per_sec_{WINDOW}"),
            "port_threshold": float(t.recon_unique_ports),
            "host_threshold": float(t.recon_unique_hosts),
        }

        return self.build_result(
            f,
            score=max(unique_ports / t.recon_unique_ports, unique_hosts / t.recon_unique_hosts),
            confidence=confidence,
            severity=self._severity(scan_kind, unique_hosts, strength),
            reason_codes=reason_codes,
            supporting=supporting,
        )

    def _severity(self, scan_kind: str, unique_hosts: float, strength: float) -> Severity:
        """Impact scales with how much of the estate was enumerated."""
        if scan_kind == "sweep" and strength >= 0.7:
            return Severity.HIGH
        if unique_hosts >= 200:
            return Severity.HIGH
        if strength >= 0.7 or unique_hosts >= 50:
            return Severity.MEDIUM
        return Severity.LOW
