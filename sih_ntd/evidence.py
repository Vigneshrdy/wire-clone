"""Evidence and lineage construction.

Evidence is a first-class output, not a log line: every alert has to answer "why
was this raised" with the actual numbers and the thresholds they were compared
against, plus enough lineage (detector version, model version, feature schema) to
reproduce the decision later.

Heavy explanation (SHAP and friends) is deliberately *not* done here. Anything
that would cost milliseconds per event belongs in an offline explanation job; this
module only assembles values the detector already computed, which is why it is
safe on the hot path.
"""

from __future__ import annotations

from .schemas import (
    EVENT_SCHEMA_VERSION,
    DetectorResult,
    EntityKind,
    Evidence,
    Lineage,
    ThreatClass,
)


def subject_of(result: DetectorResult) -> str:
    """The asset an analyst would investigate for this result.

    Source-side detectors (scanning, exfiltration, DNS) point at the source host.
    A flood points at the *target*: attributing it to one of thousands of
    (possibly spoofed) sources would both mis-word the alert and scatter one
    incident across thousands of subjects.
    """
    if result.entity_kind is EntityKind.DESTINATION:
        return result.dst_ip or result.entity_id
    return result.src_ip or result.entity_id.split("->")[0]

#: Feature-name fragments that describe a comparison rather than an observation.
_BASELINE_MARKERS = ("baseline", "zscore", "threshold", "p95")

#: One-line templates per threat class. Kept here rather than in each detector so
#: alert phrasing stays consistent across the mesh.
_SUMMARY: dict[ThreatClass, str] = {
    ThreatClass.DDOS: "Flood toward {subject}: {detail}",
    ThreatClass.RECON: "Scanning from {subject}: {detail}",
    ThreatClass.C2_BEACON: "Periodic beaconing {subject}: {detail}",
    ThreatClass.DGA: "Algorithmically-generated domain queried by {subject}: {detail}",
    ThreatClass.DNS_TUNNEL: "DNS tunnelling from {subject}: {detail}",
    ThreatClass.TLS_MALWARE: "Suspicious encrypted session {subject}: {detail}",
    ThreatClass.EXFILTRATION: "Outbound data transfer from {subject}: {detail}",
}

#: The two or three numbers that matter most per threat class, in order.
_HEADLINE: dict[ThreatClass, tuple[str, ...]] = {
    ThreatClass.DDOS: ("syn_rate_1s", "flows_per_sec_1s", "unique_src_ips_5s", "src_ip_entropy_5s"),
    ThreatClass.RECON: ("unique_dst_ports_60s", "unique_dst_ips_60s", "failed_ratio_60s"),
    ThreatClass.C2_BEACON: ("interarrival_mean", "interarrival_stdev", "periodicity_score"),
    ThreatClass.DGA: ("dga_probability", "dns_char_entropy", "dns_payload_length"),
    ThreatClass.DNS_TUNNEL: ("dns_domain_length", "dns_char_entropy", "dns_query_count_60s"),
    ThreatClass.TLS_MALWARE: ("tls_malware_probability", "tls_session_bytes"),
    ThreatClass.EXFILTRATION: (
        "bytes_out_total_300s",
        "orig_resp_byte_ratio_300s",
        "bytes_out_per_sec_60s_zscore",
    ),
}


def _fmt(value: float) -> str:
    if value >= 1000 or (value and abs(value) < 0.01):
        return f"{value:.3g}"
    return f"{value:.2f}".rstrip("0").rstrip(".")


def headline(result: DetectorResult) -> str:
    """``syn_rate_1s=2000, flows_per_sec_1s=2000, unique_src_ips_5s=250``."""
    names = _HEADLINE.get(result.threat_class, ())
    parts = [
        f"{name}={_fmt(result.supporting_features[name])}"
        for name in names
        if name in result.supporting_features
    ]
    if not parts:
        parts = [f"score={_fmt(result.score)}"]
    return ", ".join(parts)


def build_evidence(
    primary: DetectorResult,
    corroborating: list[DetectorResult] | None = None,
) -> Evidence:
    """Assemble evidence for one alert from the primary result plus corroboration.

    Observations and baseline comparisons are separated so a reader can tell
    "what was seen" from "what it was compared against" without knowing the
    feature naming convention.
    """
    corroborating = corroborating or []
    observations: dict[str, float] = {}
    baselines: dict[str, float] = {}
    for name, value in primary.supporting_features.items():
        target = baselines if any(m in name for m in _BASELINE_MARKERS) else observations
        target[name] = value

    contributions = {primary.detector_name: primary.confidence}
    reason_codes = list(primary.reason_codes)
    flow_ids = list(primary.flow_ids)
    pcaps = list(primary.pcap_references)
    for other in corroborating:
        contributions[other.detector_name] = other.confidence
        reason_codes.extend(f"{other.detector_name.upper()}:{code}" for code in other.reason_codes[:3])
        flow_ids.extend(other.flow_ids)
        pcaps.extend(other.pcap_references)

    subject = subject_of(primary)
    template = _SUMMARY.get(primary.threat_class, "{subject}: {detail}")
    summary = template.format(subject=subject, detail=headline(primary))
    if corroborating:
        classes = sorted({str(r.threat_class) for r in corroborating})
        summary += f" (corroborated by {', '.join(classes)})"

    return Evidence(
        summary=summary[:4096],
        reason_codes=list(dict.fromkeys(reason_codes))[:64],
        observations=observations,
        baseline_comparisons=baselines,
        detector_contributions=contributions,
        flow_ids=list(dict.fromkeys(flow_ids))[:128],
        pcap_references=list(dict.fromkeys(pcaps))[:16],
    )


def build_lineage(
    primary: DetectorResult,
    corroborating: list[DetectorResult] | None = None,
    pipeline_run_id: str | None = None,
) -> Lineage:
    results = [primary, *(corroborating or [])]
    return Lineage(
        detector_versions={r.detector_name: r.detector_version for r in results},
        model_versions={r.detector_name: r.model_version for r in results if r.model_version},
        feature_schema_version=primary.feature_schema_version,
        event_schema_version=EVENT_SCHEMA_VERSION,
        pipeline_run_id=pipeline_run_id,
    )
