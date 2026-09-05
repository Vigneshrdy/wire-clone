"""Volumetric and protocol DDoS detection, from the destination's perspective.

Deterministic rules plus a behavioural baseline, deliberately *not* a classifier.
A SYN rate of 28 000/s toward one host is not a probabilistic question, and a
model here would only add an unexplainable number on top of arithmetic the
analyst can check. The baseline supplies the "for this host" part that a fixed
threshold cannot.

Firing requires:

* a volumetric or protocol trigger (SYN / flow / packet / UDP rate, or
  amplification), and
* enough observed data (``coverage`` and a minimum flow count) that the rate is
  not an artefact of a nearly-empty window.

Distribution across sources and deviation from the host's own baseline raise
confidence and severity but never fire on their own.
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

# Minimum flows in the 1s window before any rate is considered meaningful.
MIN_FLOWS_1S = 20


class DDoSDetector(Detector):
    name = "ddos"
    version = "1.0.0"
    threat_class = ThreatClass.DDOS
    technique = Technique.HYBRID
    confidence_basis = ConfidenceBasis.RULE_EVIDENCE
    entity_kinds = (EntityKind.DESTINATION,)

    def evaluate(self, payload: DetectorInput) -> DetectorResult | None:
        f = payload.features
        t = self.thresholds

        flow_count_1s = f.get("flow_count_1s")
        if flow_count_1s < MIN_FLOWS_1S:
            return None

        syn_rate = f.get("syn_rate_1s")
        flow_rate = f.get("flows_per_sec_1s")
        packet_rate = f.get("packets_per_sec_1s")
        udp_rate = f.get("udp_rate_1s")
        amplification = f.get("amplification_ratio_5s")
        unique_sources = f.get("unique_src_ips_5s")
        source_entropy = f.get("src_ip_entropy_5s")
        syn_ratio = f.get("syn_ratio_5s")
        udp_ratio = f.get("udp_ratio_5s")

        # --- triggers: each yields a normalised strength in [0, 1] ---------
        triggers: list[tuple[str, float, float, float]] = []  # code, observed, threshold, strength
        if syn_rate >= t.ddos_syn_rate and syn_ratio >= 0.5:
            triggers.append(
                ("SYN_FLOOD_RATE", syn_rate, t.ddos_syn_rate,
                 stats.normalise_exceedance(syn_rate, t.ddos_syn_rate))
            )
        if udp_rate >= t.ddos_flow_rate and udp_ratio >= 0.5:
            triggers.append(
                ("UDP_FLOOD_RATE", udp_rate, t.ddos_flow_rate,
                 stats.normalise_exceedance(udp_rate, t.ddos_flow_rate))
            )
        if flow_rate >= t.ddos_flow_rate:
            triggers.append(
                ("FLOW_RATE_EXCEEDED", flow_rate, t.ddos_flow_rate,
                 stats.normalise_exceedance(flow_rate, t.ddos_flow_rate))
            )
        if packet_rate >= t.ddos_packet_rate:
            triggers.append(
                ("PACKET_RATE_EXCEEDED", packet_rate, t.ddos_packet_rate,
                 stats.normalise_exceedance(packet_rate, t.ddos_packet_rate))
            )
        if amplification >= t.ddos_amplification_ratio and udp_ratio >= 0.5:
            # Reflection/amplification: the monitored host is receiving far more
            # bytes than it sent. Observable only when both directions are visible.
            triggers.append(
                ("AMPLIFICATION_RATIO", amplification, t.ddos_amplification_ratio,
                 stats.normalise_exceedance(amplification, t.ddos_amplification_ratio))
            )
        if not triggers:
            return None

        code, observed, threshold, strength = max(triggers, key=lambda x: x[3])

        reason_codes = [c for c, *_ in triggers]
        supporting = {
            "syn_rate_1s": syn_rate,
            "flows_per_sec_1s": flow_rate,
            "packets_per_sec_1s": packet_rate,
            "udp_rate_1s": udp_rate,
            "syn_ratio_5s": syn_ratio,
            "amplification_ratio_5s": amplification,
            "unique_src_ips_5s": unique_sources,
            "src_ip_entropy_5s": source_entropy,
            "mean_packet_size_1s": f.get("mean_packet_size_1s"),
            "triggered_observed": observed,
            "triggered_threshold": threshold,
            "coverage_1s": f.get("coverage_1s"),
        }

        # --- corroboration: distribution and baseline deviation -----------
        confidence = 0.5 + 0.4 * strength  # rule strength dominates
        distributed = (
            unique_sources >= t.ddos_min_unique_sources and source_entropy >= t.ddos_source_entropy
        )
        if distributed:
            reason_codes.append("DISTRIBUTED_SOURCES")
            confidence += 0.05

        baseline_warm = f.get("flows_per_sec_60s_baseline_warm") == 1.0
        baseline_mean = f.get("flows_per_sec_60s_baseline_mean")
        if baseline_warm:
            supporting["flows_per_sec_60s_baseline_mean"] = baseline_mean
            supporting["flows_per_sec_60s_zscore"] = f.get("flows_per_sec_60s_zscore")
            multiple = stats.ratio(f.get("flows_per_sec_60s"), baseline_mean)
            supporting["observed_over_baseline"] = multiple
            if multiple >= t.ddos_baseline_multiplier:
                reason_codes.append("BASELINE_EXCEEDED")
                confidence += 0.05
        else:
            # Explicit: no baseline is not evidence of an attack.
            reason_codes.append("BASELINE_COLD")

        severity = self._severity(strength, distributed, baseline_warm)
        return self.build_result(
            f,
            score=observed / threshold if threshold else observed,
            confidence=min(0.99, confidence),
            severity=severity,
            reason_codes=reason_codes,
            supporting=supporting,
        )

    def _severity(self, strength: float, distributed: bool, baseline_warm: bool) -> Severity:
        """Impact, not certainty: how much traffic and how many sources.

        A 1.2x threshold breach from one source is a nuisance; a 10x breach from
        thousands of sources is a service outage.
        """
        if strength >= 0.9:
            severity = Severity.CRITICAL if distributed else Severity.HIGH
        elif strength >= 0.7:
            severity = Severity.HIGH if distributed else Severity.MEDIUM
        else:
            severity = Severity.MEDIUM if distributed else Severity.LOW
        if not baseline_warm and severity is Severity.CRITICAL:
            # Without a baseline we cannot claim this is abnormal *for this host*.
            return Severity.HIGH
        return severity
