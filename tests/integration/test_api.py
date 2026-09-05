"""API contract tests via FastAPI's TestClient (no network, no running server)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sih_ntd.api import app, get_state
from sih_ntd.sensor.synthetic import generate
from tests.conftest import syn_flood_events


@pytest.fixture
def client(settings, tmp_path):
    """A client whose AppState points at a temp store seeded with real alerts."""
    from sih_ntd.pipeline import Pipeline
    from sih_ntd.store import Store

    store = Store(settings.store.path, settings=settings)
    Pipeline(settings, store=store, publish_alerts=False).handle_events(
        syn_flood_events(3000) + generate("scan_vertical", count=400, seed=5)
    )
    store.close()
    with TestClient(app) as client:
        yield client


def test_health_reports_schema_versions(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["schema_versions"] == {"event": "1.0.0", "feature": "1.0.0", "alert": "1.0.0"}


def test_ready_exposes_unavailable_detectors_honestly(client):
    body = client.get("/ready").json()
    assert set(body["detectors_unavailable"]) == {"dga", "tls_malware"}
    assert body["store"]["counts"]["alerts"] > 0


def test_metrics_is_prometheus_text(client):
    text = client.get("/metrics").text
    assert "# TYPE sih_alerts_total counter" in text
    assert "sih_detector_state" in text


def test_metrics_never_contains_an_ip_address(client):
    """Cardinality guard, asserted at the exposition layer."""
    assert "203.0.113." not in client.get("/metrics").text


def test_list_alerts_with_evidence_and_filters(client):
    body = client.get("/api/v1/alerts", params={"limit": 10}).json()
    assert body["total"] >= 1
    alert = body["alerts"][0]
    assert alert["evidence"]["summary"]
    assert alert["evidence"]["reason_codes"]
    assert alert["lineage"]["feature_schema_version"] == "1.0.0"

    ddos = client.get("/api/v1/alerts", params={"threat_class": "DDOS"}).json()
    assert all(a["threat_class"] == "DDOS" for a in ddos["alerts"])
    filtered = client.get("/api/v1/alerts", params={"min_confidence": 0.99}).json()
    assert all(a["confidence"] >= 0.99 for a in filtered["alerts"])


def test_alert_detail_includes_decision_history(client):
    alert_id = client.get("/api/v1/alerts").json()["alerts"][0]["alert_id"]
    body = client.get(f"/api/v1/alerts/{alert_id}").json()
    assert body["alert"]["alert_id"] == alert_id
    assert body["history"][0]["kind"] == "CREATED"
    assert client.get("/api/v1/alerts/does-not-exist").status_code == 404


def test_alert_status_transition(client):
    alert_id = client.get("/api/v1/alerts").json()["alerts"][0]["alert_id"]
    response = client.post(
        f"/api/v1/alerts/{alert_id}/status", json={"status": "TRIAGED", "actor": "analyst"}
    )
    assert response.status_code == 200
    assert client.get(f"/api/v1/alerts/{alert_id}").json()["alert"]["status"] == "TRIAGED"


def test_alerts_summary_and_flows(client):
    summary = client.get("/api/v1/alerts/summary").json()
    assert summary["by_threat_class"]
    flows = client.get("/api/v1/flows", params={"limit": 5}).json()
    assert flows["count"] > 0
    assert "dns_query" in flows["flows"][0], "flow rows expose metadata only"


def test_detector_inventory_reports_states_and_reasons(client):
    detectors = {d["name"]: d for d in client.get("/api/v1/detectors").json()["detectors"]}
    assert detectors["dga"]["state"] == "UNAVAILABLE"
    assert detectors["dga"]["state_reason"]
    assert detectors["ddos"]["state"] == "READY"
    assert detectors["recon"]["technique"] == "RULE"


def test_model_health_joins_runtime_and_registry(client):
    entries = {d["detector"]: d for d in client.get("/api/v1/model-health").json()["detectors"]}
    assert entries["dga"]["champion_model_version"] is None
    assert entries["ddos"]["running_model_version"] is None  # rule-based, no model


def test_feedback_is_recorded_as_a_training_candidate_only(client):
    alert_id = client.get("/api/v1/alerts").json()["alerts"][0]["alert_id"]
    response = client.post(
        "/api/v1/feedback",
        json={"alert_id": alert_id, "label": "FALSE_POSITIVE", "analyst_id": "analyst-1",
              "notes": "known load test"},
    )
    assert response.status_code == 201
    assert "training candidate" in response.json()["effect"]
    assert client.get("/api/v1/feedback").json()["count"] == 1


def test_feedback_for_an_unknown_alert_is_rejected(client):
    response = client.post(
        "/api/v1/feedback", json={"alert_id": "nope", "label": "TRUE_POSITIVE"}
    )
    assert response.status_code == 404


def test_false_negative_feedback_requires_a_class(client):
    alert_id = client.get("/api/v1/alerts").json()["alerts"][0]["alert_id"]
    response = client.post(
        "/api/v1/feedback", json={"alert_id": alert_id, "label": "FALSE_NEGATIVE"}
    )
    assert response.status_code == 422


def test_promoting_an_unregistered_model_is_a_404(client):
    response = client.post(
        "/api/v1/models/dga/promote", json={"model_version": "nope", "reason": "x"}
    )
    assert response.status_code == 404


def test_drift_endpoint_states_that_signals_do_not_act(client):
    body = client.get("/api/v1/drift").json()
    assert "never trigger" in body["note"]


def test_incidents_endpoint(client):
    body = client.get("/api/v1/incidents").json()
    assert "incidents" in body
    assert client.get("/api/v1/incidents/missing").status_code == 404
