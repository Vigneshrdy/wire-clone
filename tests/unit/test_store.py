"""Store: round-trips, idempotent replay, append-only audit trail, retention."""

from __future__ import annotations

from sih_ntd.schemas import (
    Alert,
    AlertStatus,
    AnalystFeedback,
    BenchmarkResult,
    ConfidenceBasis,
    DriftEvent,
    DriftType,
    EntityKind,
    Evidence,
    FeedbackLabel,
    Severity,
    Technique,
    ThreatClass,
)
from tests.conftest import T0, flow


def make_alert(**overrides) -> Alert:
    payload = dict(
        timestamp=T0, first_seen=T0, last_seen=T0, threat_class=ThreatClass.DDOS,
        confidence=0.91, confidence_basis=ConfidenceBasis.RULE_EVIDENCE,
        severity=Severity.HIGH, entity_kind=EntityKind.DESTINATION, entity_id="10.0.0.9",
        detector_name="ddos", detector_version="1.0.0", technique=Technique.HYBRID,
        src_ip="203.0.113.5", dst_ip="10.0.0.9",
        evidence=Evidence(
            summary="Flood toward 10.0.0.9", reason_codes=["SYN_FLOOD_RATE"],
            observations={"syn_rate_1s": 2000.0},
            baseline_comparisons={"triggered_threshold": 500.0},
        ),
    )
    payload.update(overrides)
    return Alert(**payload)


def test_replaying_the_same_event_inserts_once(store):
    event = flow()
    assert store.insert_events([event]) == 1
    assert store.insert_events([event]) == 0, "deterministic event_id must dedupe replays"
    assert store.health()["counts"]["events"] == 1


def test_alert_round_trip_preserves_evidence(store):
    alert = make_alert()
    store.insert_alerts([alert])
    loaded = store.get_alert(alert.alert_id)
    assert loaded is not None
    assert loaded.evidence.observations["syn_rate_1s"] == 2000.0
    assert loaded.evidence.baseline_comparisons["triggered_threshold"] == 500.0
    assert loaded.lineage.event_schema_version == "1.0.0"


def test_touch_alert_advances_counters_and_records_history(store):
    alert = make_alert()
    store.insert_alerts([alert])
    store.touch_alert(alert.alert_id, T0 + 30, dedup_count=7, event_count=7)
    loaded = store.get_alert(alert.alert_id)
    assert loaded.dedup_count == 7
    kinds = [row["kind"] for row in store.alert_history(alert.alert_id)]
    assert kinds == ["CREATED", "DEDUPED"], "audit trail must be append-only"


def test_status_change_is_audited(store):
    alert = make_alert()
    store.insert_alerts([alert])
    assert store.set_alert_status(alert.alert_id, AlertStatus.DISMISSED, "analyst")
    assert store.get_alert(alert.alert_id).status is AlertStatus.DISMISSED
    assert "STATUS" in [row["kind"] for row in store.alert_history(alert.alert_id)]
    assert not store.set_alert_status("nonexistent", AlertStatus.TRIAGED)


def test_alert_filters(store):
    store.insert_alerts([
        make_alert(),
        make_alert(threat_class=ThreatClass.RECON, severity=Severity.LOW,
                   src_ip="203.0.113.77", entity_kind=EntityKind.HOST, entity_id="203.0.113.77",
                   confidence=0.6, evidence=Evidence(summary="scan")),
    ])
    assert len(store.query_alerts(threat_class="DDOS")) == 1
    assert len(store.query_alerts(min_confidence=0.9)) == 1
    assert len(store.query_alerts(src_ip="203.0.113.77")) == 1
    assert store.alert_summary()["by_severity"] == {"HIGH": 1, "LOW": 1}


def test_feedback_lifecycle(store):
    alert = make_alert()
    store.insert_alerts([alert])
    feedback = AnalystFeedback(
        alert_id=alert.alert_id, label=FeedbackLabel.FALSE_POSITIVE, analyst_id="analyst-1"
    )
    store.insert_feedback(feedback)
    assert len(store.query_feedback(unconsumed_only=True)) == 1
    store.mark_feedback_consumed([feedback.feedback_id], "ds-1")
    assert store.query_feedback(unconsumed_only=True) == []


def test_drift_and_benchmark_round_trip(store):
    store.insert_drift_events([
        DriftEvent(detector="dga", drift_type=DriftType.FEATURE_DISTRIBUTION, metric="psi",
                   score=0.4, threshold=0.2, window="1h", feature="dns_char_entropy")
    ])
    events = store.query_drift(detector="dga")
    assert events[0].breached and events[0].feature == "dns_char_entropy"

    store.insert_benchmark(BenchmarkResult(
        name="unit", events=100, duration_seconds=1.0, events_per_second=100.0,
        hardware="test", configuration={"windows": "1.0"},
    ))
    assert store.query_benchmarks()[0]["configuration"] == {"windows": "1.0"}


def test_prune_removes_telemetry_but_keeps_alerts(store):
    store.insert_events([flow(ts=T0)])
    store.insert_alerts([make_alert()])
    deleted = store.prune(T0 + 1)
    assert deleted["events"] == 1
    assert store.health()["counts"]["alerts"] == 1, "alerts are the record; they are not pruned"
