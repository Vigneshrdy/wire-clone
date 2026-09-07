"""Fusion: dedup, corroboration, severity-vs-confidence, incidents."""

from __future__ import annotations

import pytest

from sih_ntd.fusion import ThreatFusion, score_severity
from sih_ntd.config import Settings
from sih_ntd.schemas import (
    ConfidenceBasis,
    DetectorResult,
    EntityKind,
    Severity,
    Technique,
    ThreatClass,
)
from tests.conftest import T0


def result(
    detector: str = "ddos",
    threat: ThreatClass = ThreatClass.DDOS,
    ts: float = T0,
    *,
    confidence: float = 0.9,
    severity: Severity = Severity.MEDIUM,
    entity: str = "10.0.0.9",
    kind: EntityKind = EntityKind.DESTINATION,
    src: str | None = "203.0.113.5",
    dst: str | None = "10.0.0.9",
    shadow: bool = False,
) -> DetectorResult:
    return DetectorResult(
        detector_name=detector, detector_version="1.0.0", threat_class=threat,
        technique=Technique.RULE, score=1.0, confidence=confidence,
        confidence_basis=ConfidenceBasis.RULE_EVIDENCE, severity_hint=severity,
        timestamp=ts, entity_kind=kind, entity_id=entity, window_seconds=300.0,
        src_ip=src, dst_ip=dst, supporting_features={"syn_rate_1s": 2000.0},
        reason_codes=["SYN_FLOOD_RATE"], shadow=shadow,
    )


def test_first_result_becomes_an_alert(fusion):
    outcome = fusion.ingest([result()])
    assert len(outcome.alerts) == 1
    assert outcome.alerts[0].evidence.summary.startswith("Flood toward 10.0.0.9")


def test_repeat_within_dedup_window_becomes_a_touch_not_an_alert(fusion):
    fusion.ingest([result(ts=T0)])
    outcome = fusion.ingest([result(ts=T0 + 5)])
    assert outcome.alerts == []
    assert outcome.touches[0].dedup_count == 2


def test_repeat_after_dedup_window_is_a_new_alert(fusion, settings):
    fusion.ingest([result(ts=T0)])
    later = T0 + settings.fusion.dedup_window_seconds + 1
    assert len(fusion.ingest([result(ts=later)]).alerts) == 1


def test_cross_detector_corroboration_raises_confidence_and_opens_an_incident(fusion, settings):
    fusion.ingest([result("dga", ThreatClass.DGA, T0, kind=EntityKind.HOST,
                          entity="10.0.0.5", src="10.0.0.5", confidence=0.9)])
    outcome = fusion.ingest([result("c2_beacon", ThreatClass.C2_BEACON, T0 + 10,
                                    kind=EntityKind.HOST, entity="10.0.0.5", src="10.0.0.5",
                                    confidence=0.9)])
    alert = outcome.alerts[0]
    assert alert.confidence == pytest.approx(0.9 + settings.fusion.corroboration_bonus)
    assert alert.confidence_basis is ConfidenceBasis.FUSION
    assert alert.contributing_detectors == ["dga"]
    assert outcome.incidents and len(outcome.incidents[0].threat_classes) == 2
    assert alert.incident_id == outcome.incidents[0].incident_id


def test_confidence_is_capped_however_many_detectors_agree(fusion, settings):
    """Six corroborating detectors must not push confidence to 1.0."""
    classes = [
        ThreatClass.DGA, ThreatClass.C2_BEACON, ThreatClass.DNS_TUNNEL,
        ThreatClass.RECON, ThreatClass.EXFILTRATION, ThreatClass.TLS_MALWARE,
    ]
    alerts = []
    for index, threat in enumerate(classes):
        outcome = fusion.ingest([
            result(f"det{index}", threat, T0 + index, kind=EntityKind.HOST,
                   entity="10.0.0.5", src="10.0.0.5", confidence=0.95)
        ])
        alerts.extend(outcome.alerts)
    assert alerts, "expected alerts from the corroborating detectors"
    assert max(a.confidence for a in alerts) <= settings.fusion.max_confidence


def test_low_confidence_results_do_not_alert(fusion, settings):
    weak = settings.fusion.min_alert_confidence - 0.01
    assert fusion.ingest([result(confidence=weak)]).alerts == []


def test_shadow_results_never_produce_alerts(fusion):
    """The mechanism that stops a challenger model from paging anyone."""
    assert fusion.ingest([result(shadow=True)]).alerts == []


def test_flood_is_attributed_to_the_target_not_a_spoofed_source(fusion):
    outcome = fusion.ingest([result(kind=EntityKind.DESTINATION, src="203.0.113.5", dst="10.0.0.9")])
    assert outcome.alerts[0].correlation_id == "10.0.0.9"


def test_severity_is_not_confidence():
    """High confidence in a small event stays low severity."""
    assert score_severity(ThreatClass.RECON, Severity.LOW, 0, 0.99) is Severity.LOW
    assert score_severity(ThreatClass.DDOS, Severity.CRITICAL, 0, 0.55) is Severity.CRITICAL


def test_severity_floor_for_compromise_implying_classes():
    assert score_severity(ThreatClass.C2_BEACON, Severity.LOW, 0, 0.6) is Severity.MEDIUM
    assert score_severity(ThreatClass.RECON, Severity.LOW, 0, 0.6) is Severity.LOW


def test_severity_escalates_on_corroboration():
    assert score_severity(ThreatClass.RECON, Severity.LOW, 2, 0.6) is Severity.MEDIUM
    assert score_severity(ThreatClass.DDOS, Severity.CRITICAL, 3, 0.9) is Severity.CRITICAL


def test_expire_releases_state(fusion, settings):
    fusion.ingest([result()])
    assert fusion.tracked_subjects == 1
    fusion.expire(T0 + settings.fusion.incident_idle_seconds + 10)
    assert fusion.tracked_subjects == 0


def test_fusion_state_is_lru_bounded_under_high_cardinality_results():
    bounded = ThreatFusion(Settings(windows={"max_tracked_entities": 100}))
    for index in range(150):
        bounded.ingest([
            result(
                ts=T0 + index,
                entity=f"10.0.0.{index}",
                dst=f"10.0.0.{index}",
            )
        ])
    assert bounded.tracked_subjects == 100
    assert bounded.tracked_dedup_keys == 100


def test_fusion_resets_incident_group_after_idle_gap(settings):
    fusion = ThreatFusion(settings)
    fusion.ingest([result("dga", ThreatClass.DGA, T0, kind=EntityKind.HOST, entity="10.0.0.5")])
    first = fusion.ingest([
        result("c2", ThreatClass.C2_BEACON, T0 + 1, kind=EntityKind.HOST, entity="10.0.0.5")
    ]).incidents[0]
    later = T0 + settings.fusion.incident_idle_seconds + 10
    fusion.ingest([result("dga", ThreatClass.DGA, later, kind=EntityKind.HOST, entity="10.0.0.5")])
    second = fusion.ingest([
        result("c2", ThreatClass.C2_BEACON, later + 1, kind=EntityKind.HOST, entity="10.0.0.5")
    ]).incidents[0]
    assert second.incident_id != first.incident_id
