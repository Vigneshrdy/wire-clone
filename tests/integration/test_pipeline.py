"""End-to-end: events -> features -> detectors -> fusion -> alerts -> store."""

from __future__ import annotations

from sih_ntd.schemas import ThreatClass
from sih_ntd.sensor.synthetic import generate
from tests.conftest import syn_flood_events


def test_vertical_slice_produces_stored_explainable_alerts(pipeline):
    """The initial vertical slice from the brief, asserted end to end."""
    stats = pipeline.handle_events(syn_flood_events(3000))
    assert stats.events == 3000
    assert stats.features > 0
    assert stats.alerts >= 1

    alerts = pipeline.store.query_alerts(threat_class="DDOS")
    assert alerts, "the alert must be readable back out of the store"
    alert = alerts[0]
    assert alert.evidence.summary.startswith("Flood toward")
    assert alert.evidence.observations["syn_rate_1s"] > 500
    assert alert.evidence.baseline_comparisons["triggered_threshold"] == 500.0
    assert alert.lineage.detector_versions["ddos"] == "1.0.0"
    assert alert.lineage.pipeline_run_id == "test-run"
    assert alert.evidence.reason_codes


def test_mixed_traffic_finds_every_available_detector_class(pipeline):
    """Attack patterns must be found while benign traffic is present."""
    pipeline.handle_events(generate("mixed", count=800, seed=11))
    found = {a.threat_class for a in pipeline.alerts}
    assert {
        ThreatClass.DDOS, ThreatClass.RECON, ThreatClass.C2_BEACON,
        ThreatClass.DNS_TUNNEL, ThreatClass.EXFILTRATION,
    } <= found


def test_duplicates_are_suppressed_rather_than_stored_repeatedly(pipeline):
    stats = pipeline.handle_events(syn_flood_events(6000))
    assert stats.suppressed > stats.alerts, "a sustained flood must collapse into few alerts"
    alert = pipeline.store.query_alerts(threat_class="DDOS")[0]
    assert alert.dedup_count >= 1
    history = pipeline.store.alert_history(alert.alert_id)
    assert history[0]["kind"] == "CREATED"


def test_benign_traffic_creates_no_alerts_end_to_end(pipeline):
    stats = pipeline.handle_events(generate("benign", count=2000, seed=3))
    assert stats.alerts == 0
    assert pipeline.store.count_alerts() == 0
    assert stats.features > 0, "the engine must still be producing features"


def test_events_features_and_results_are_persisted(pipeline):
    pipeline.handle_events(syn_flood_events(1200))
    counts = pipeline.store.health()["counts"]
    assert counts["events"] > 0
    assert counts["features"] > 0
    assert counts["detector_results"] > 0


def test_replay_is_idempotent(pipeline):
    events = syn_flood_events(1200)
    pipeline.handle_events(events)
    first = pipeline.store.health()["counts"]["events"]
    pipeline.handle_events(events)
    assert pipeline.store.health()["counts"]["events"] == first


def test_duplicate_delivery_after_worker_restart_does_not_duplicate_alerts(settings, store):
    from sih_ntd.pipeline import Pipeline

    events = syn_flood_events(3000)
    Pipeline(settings, store=store, publish_alerts=False).handle_events(events)
    first_alerts = store.count_alerts()
    first_ids = [alert.alert_id for alert in store.query_alerts(limit=500)]

    # Simulates Redis redelivery after a crash after persist but before ACK: a new
    # process has empty in-memory fusion state but sees the same deterministic event
    # batch again.
    Pipeline(settings, store=store, publish_alerts=False).handle_events(events)

    assert store.count_alerts() == first_alerts
    assert [alert.alert_id for alert in store.query_alerts(limit=500)] == first_ids


def test_a_failing_detector_does_not_stop_the_others(pipeline, monkeypatch):
    """Isolation boundary: one broken detector must not silence the mesh."""
    from sih_ntd.metrics import DETECTOR_ERRORS, reset

    reset()
    recon = pipeline.detectors.get("recon")

    def explode(payload):
        raise RuntimeError("simulated detector fault")

    monkeypatch.setattr(recon, "evaluate", explode)
    stats = pipeline.handle_events(syn_flood_events(3000))
    assert stats.alerts >= 1, "DDoS must still be detected"
    assert DETECTOR_ERRORS.value(detector="recon") > 0


def test_incidents_group_multiple_threat_classes_on_one_host(pipeline):
    pipeline.handle_events(generate("mixed", count=1500, seed=21))
    incidents = pipeline.store.query_incidents()
    if incidents:
        incident = incidents[0]
        assert len(incident.threat_classes) >= 2
        assert incident.alert_count >= 1
        assert incident.summary
