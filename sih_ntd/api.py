"""FastAPI backend: versioned REST + WebSocket. No frontend (out of scope).

Everything a dashboard will need is exposed as JSON: alerts with full evidence,
incidents, flows, detector states, model registry contents, drift signals,
benchmark results, and a live alert WebSocket. Adding a UI later requires no
change here.

Security posture (see docs/SECURITY_MODEL.md): the prototype binds to loopback and
has **no authentication**. Every route is read-only except ``POST /feedback``,
``POST /replay/start`` and the model lifecycle routes. Before this is exposed
beyond localhost it needs an auth layer -- the mutating routes can promote a model
and start a replay job.
"""

from __future__ import annotations

import asyncio
import json
import platform
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import metrics as metrics_module
from .config import Settings, Streams, get_settings
from .detectors import build_default_registry
from .errors import PromotionBlocked
from .logging_conf import configure_logging, get_logger
from .ml.governance import PromotionGate
from .ml.registry import ModelRegistry
from .ml.shadow import compare as compare_shadow
from .schemas import (
    ALERT_SCHEMA_VERSION,
    EVENT_SCHEMA_VERSION,
    FEATURE_SCHEMA_VERSION,
    Alert,
    AlertStatus,
    AnalystFeedback,
    DetectorState,
    Incident,
    ModelStatus,
)
from .store import Store
from .streaming import PAYLOAD_FIELD, StreamClient

log = get_logger(__name__)


class AppState:
    """Process-wide singletons. Built once at startup, injected into routes."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store = Store(settings=settings)
        self.registry = ModelRegistry(settings=settings)
        self.detectors = build_default_registry(settings)
        self.gate = PromotionGate(settings)
        self.stream = StreamClient(settings)
        self.replay_status: dict[str, Any] = {"state": "idle"}


def get_state() -> AppState:  # replaced at startup
    raise RuntimeError("application state not initialised")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    settings = get_settings()
    state = AppState(settings)
    app.dependency_overrides[get_state] = lambda: state
    log.info(
        "api starting",
        extra={"store": str(state.store.path), "detectors": len(state.detectors)},
    )
    yield
    state.store.close()


app = FastAPI(
    title="SIH 26145 -- Passive Cyber Threat Detection",
    version="0.1.0",
    summary="Passive detection of cyber threats in unidirectional IP traffic",
    lifespan=lifespan,
)
StateDep = Annotated[AppState, Depends(get_state)]
PREFIX = "/api/v1"


# --- health / observability -----------------------------------------------
@app.get("/health", tags=["ops"])
def health() -> dict[str, Any]:
    """Liveness. Deliberately does not touch Redis or the store."""
    return {
        "status": "ok",
        "schema_versions": {
            "event": EVENT_SCHEMA_VERSION,
            "feature": FEATURE_SCHEMA_VERSION,
            "alert": ALERT_SCHEMA_VERSION,
        },
    }


@app.get("/ready", tags=["ops"])
def ready(state: StateDep) -> dict[str, Any]:
    """Readiness: dependencies actually reachable, and which detectors can run."""
    redis_ok = state.stream.ping()
    store_health = state.store.health()
    detectors = {d.name: str(d.state()) for d in state.detectors}
    unavailable = {name: st for name, st in detectors.items() if st != DetectorState.READY}
    return {
        # Redis is required for the streaming worker but not for serving stored
        # alerts, so the API is "ready" with a degraded flag rather than failing.
        "status": "ok" if redis_ok else "degraded",
        "redis": redis_ok,
        "store": store_health,
        "detectors": detectors,
        "detectors_unavailable": unavailable,
    }


@app.get("/metrics", response_class=PlainTextResponse, tags=["ops"])
def prometheus_metrics(state: StateDep) -> str:
    for stream in (Streams.NORMALIZED, Streams.ALERTS):
        try:
            state.stream.lag(stream)
        except Exception:  # noqa: BLE001 -- metrics must never fail the scrape
            pass
    for detector in state.detectors:
        metrics_module.DETECTOR_STATE.set(
            1 if detector.state() is DetectorState.READY else 0, detector=detector.name
        )
        if detector.model_version:
            metrics_module.MODEL_INFO.set(
                1, detector=detector.name, model_version=detector.model_version
            )
    return metrics_module.render()


# --- alerts ----------------------------------------------------------------
@app.get(f"{PREFIX}/alerts", tags=["alerts"])
def list_alerts(
    state: StateDep,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    threat_class: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    src_ip: str | None = None,
    since: float | None = None,
    until: float | None = None,
    min_confidence: float | None = Query(default=None, ge=0, le=1),
    incident_id: str | None = None,
) -> dict[str, Any]:
    alerts = state.store.query_alerts(
        limit=limit, offset=offset, threat_class=threat_class, severity=severity,
        status=status, src_ip=src_ip, since=since, until=until,
        min_confidence=min_confidence, incident_id=incident_id,
    )
    return {
        "count": len(alerts),
        "total": state.store.count_alerts(threat_class=threat_class, severity=severity),
        "limit": limit,
        "offset": offset,
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }


@app.get(f"{PREFIX}/alerts/summary", tags=["alerts"])
def alerts_summary(state: StateDep) -> dict[str, Any]:
    return state.store.alert_summary()


@app.get(f"{PREFIX}/alerts/{{alert_id}}", tags=["alerts"])
def get_alert(alert_id: str, state: StateDep) -> dict[str, Any]:
    alert = state.store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return {
        "alert": alert.model_dump(mode="json"),
        # Append-only decision history: creation, dedup bumps, status changes.
        "history": state.store.alert_history(alert_id),
    }


class StatusUpdate(BaseModel):
    status: AlertStatus
    actor: str = Field(default="api", max_length=256)


@app.post(f"{PREFIX}/alerts/{{alert_id}}/status", tags=["alerts"])
def set_alert_status(alert_id: str, update: StatusUpdate, state: StateDep) -> dict[str, Any]:
    if not state.store.set_alert_status(alert_id, update.status, update.actor):
        raise HTTPException(status_code=404, detail="alert not found")
    return {"alert_id": alert_id, "status": update.status}


# --- incidents / flows ----------------------------------------------------
@app.get(f"{PREFIX}/incidents", tags=["incidents"])
def list_incidents(
    state: StateDep,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    incidents: list[Incident] = state.store.query_incidents(limit=limit, offset=offset)
    return {"count": len(incidents), "incidents": [i.model_dump(mode="json") for i in incidents]}


@app.get(f"{PREFIX}/incidents/{{incident_id}}", tags=["incidents"])
def get_incident(incident_id: str, state: StateDep) -> dict[str, Any]:
    incident = state.store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    alerts: list[Alert] = state.store.query_alerts(limit=500, incident_id=incident_id)
    return {
        "incident": incident.model_dump(mode="json"),
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }


@app.get(f"{PREFIX}/flows", tags=["flows"])
def list_flows(
    state: StateDep,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    src_ip: str | None = None,
    dst_ip: str | None = None,
    since: float | None = None,
) -> dict[str, Any]:
    """Normalized flow metadata. No payload is stored, so none can be returned."""
    flows = state.store.query_flows(
        limit=limit, offset=offset, src_ip=src_ip, dst_ip=dst_ip, since=since
    )
    return {"count": len(flows), "flows": flows}


# --- detectors / models ---------------------------------------------------
@app.get(f"{PREFIX}/detectors", tags=["models"])
def list_detectors(state: StateDep) -> dict[str, Any]:
    """Detector inventory including honest UNAVAILABLE states and their reasons."""
    return {"detectors": [m.model_dump(mode="json") for m in state.detectors.metadata()]}


@app.get(f"{PREFIX}/models", tags=["models"])
def list_models(state: StateDep) -> dict[str, Any]:
    return {"feature_schema_version": FEATURE_SCHEMA_VERSION, "registry": state.registry.summary()}


@app.get(f"{PREFIX}/models/{{detector}}", tags=["models"])
def detector_models(detector: str, state: StateDep) -> dict[str, Any]:
    models = state.registry.list_models(detector)
    if not models:
        raise HTTPException(status_code=404, detail=f"no models registered for {detector!r}")
    return {
        "detector": detector,
        "models": [m.model_dump(mode="json") for m in models],
        "promotion_history": [
            r.model_dump(mode="json") for r in state.registry.promotion_history(detector)
        ],
    }


@app.get(f"{PREFIX}/model-health", tags=["models"])
def model_health(state: StateDep) -> dict[str, Any]:
    """Per-detector runtime state joined to registry status -- the operator view."""
    out = []
    for detector in state.detectors:
        champion = state.registry.champion(detector.name)
        out.append(
            {
                "detector": detector.name,
                "state": str(detector.state()),
                "state_reason": detector.state_reason(),
                "technique": str(detector.technique),
                "running_model_version": detector.model_version,
                "champion_model_version": champion.model_version if champion else None,
                "champion_metrics": dict(champion.metrics) if champion else {},
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
            }
        )
    return {"detectors": out}


@app.post(f"{PREFIX}/models/{{detector}}/evaluate", tags=["models"])
def evaluate_model(
    detector: str,
    state: StateDep,
    model_version: str | None = None,
) -> dict[str, Any]:
    """Run the governance gates against a candidate. Never changes any status."""
    metadata = (
        state.registry.get(detector, model_version)
        if model_version
        else next(
            (m for m in state.registry.list_models(detector) if m.status == ModelStatus.CANDIDATE),
            None,
        )
    )
    if metadata is None:
        raise HTTPException(status_code=404, detail="no such model / no candidate to evaluate")
    report = state.gate.evaluate(metadata, state.registry.champion(detector))
    return {
        "detector": detector,
        "model_version": metadata.model_version,
        "metrics": dict(metadata.metrics),
        "gate": report.as_dict(),
        "shadow": compare_shadow(detector, state.store, state.registry).as_dict(),
    }


class PromoteRequest(BaseModel):
    model_version: str = Field(max_length=256)
    actor: str = Field(default="api", max_length=256)
    reason: str = Field(default="", max_length=4096)
    to_status: ModelStatus = ModelStatus.CHAMPION
    #: Gate names the operator explicitly accepts as failing. Recorded in the
    #: promotion history; never applied implicitly.
    acknowledge: list[str] = Field(default_factory=list, max_length=16)
    regression_tests_passed: bool | None = None


@app.post(f"{PREFIX}/models/{{detector}}/promote", tags=["models"])
def promote_model(detector: str, request: PromoteRequest, state: StateDep) -> dict[str, Any]:
    """Explicit promotion. Gates must pass (or be explicitly acknowledged).

    Nothing else in the system calls this: drift signals, training runs and shadow
    comparisons cannot promote a model. That separation is the anti-poisoning
    control described in docs/CONTINUOUS_LEARNING.md.
    """
    metadata = state.registry.get(detector, request.model_version)
    if metadata is None:
        raise HTTPException(status_code=404, detail="model not registered")
    report = state.gate.evaluate(
        metadata,
        state.registry.champion(detector),
        regression_tests_passed=request.regression_tests_passed,
        acknowledge=set(request.acknowledge),
    )
    if not report.passed:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "promotion blocked by governance gates",
                "failures": report.failures,
                "hint": "fix the model, or acknowledge specific gates with a reason",
            },
        )
    updated = state.registry.set_status(
        detector, request.model_version, request.to_status,
        actor=request.actor, reason=request.reason,
        gate_results={
            **report.results,
            **{f"acknowledged:{k}": False for k in report.acknowledged},
        },
    )
    return {
        "detector": detector,
        "model": updated.model_dump(mode="json"),
        "gate": report.as_dict(),
        "note": "restart detection workers to load the new champion",
    }


class RollbackRequest(BaseModel):
    actor: str = Field(default="api", max_length=256)
    reason: str = Field(default="rollback", max_length=4096)


@app.post(f"{PREFIX}/models/{{detector}}/rollback", tags=["models"])
def rollback_model(detector: str, request: RollbackRequest, state: StateDep) -> dict[str, Any]:
    try:
        restored = state.registry.rollback(detector, actor=request.actor, reason=request.reason)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"detector": detector, "champion": restored.model_dump(mode="json")}


# --- drift / feedback / benchmarks ---------------------------------------
@app.get(f"{PREFIX}/drift", tags=["ml"])
def list_drift(
    state: StateDep,
    limit: int = Query(default=50, ge=1, le=500),
    detector: str | None = None,
) -> dict[str, Any]:
    events = state.store.query_drift(limit=limit, detector=detector)
    return {
        "count": len(events),
        "note": "drift events are signals only; they never trigger retraining or promotion",
        "events": [e.model_dump(mode="json") for e in events],
    }


@app.post(f"{PREFIX}/feedback", status_code=201, tags=["ml"])
def submit_feedback(feedback: AnalystFeedback, state: StateDep) -> dict[str, Any]:
    """Record an analyst judgement as a *training candidate*.

    This does not change any model, threshold or alert verdict. It is stored, and a
    later offline dataset build may use it -- see docs/CONTINUOUS_LEARNING.md.
    """
    if state.store.get_alert(feedback.alert_id) is None:
        raise HTTPException(status_code=404, detail="alert not found")
    state.store.insert_feedback(feedback)
    metrics_module.FEEDBACK_TOTAL.inc(label=str(feedback.label))
    return {
        "feedback_id": feedback.feedback_id,
        "stored": True,
        "effect": "training candidate only; production models unchanged",
    }


@app.get(f"{PREFIX}/feedback", tags=["ml"])
def list_feedback(
    state: StateDep,
    limit: int = Query(default=100, ge=1, le=1000),
    unconsumed_only: bool = False,
) -> dict[str, Any]:
    rows = state.store.query_feedback(limit=limit, unconsumed_only=unconsumed_only)
    return {"count": len(rows), "feedback": rows}


@app.get(f"{PREFIX}/benchmarks", tags=["ops"])
def list_benchmarks(state: StateDep, limit: int = Query(default=20, ge=1, le=100)) -> dict[str, Any]:
    results = state.store.query_benchmarks(limit=limit)
    return {
        "count": len(results),
        "hardware_note": platform.platform(),
        "results": results,
    }


# --- replay ---------------------------------------------------------------
class ReplayRequest(BaseModel):
    scenario: str = Field(default="mixed", max_length=64)
    count: int = Field(default=2000, ge=1, le=200_000)
    seed: int = 1337
    pcap: str | None = Field(default=None, max_length=1024)


@app.post(f"{PREFIX}/replay/start", status_code=202, tags=["replay"])
async def start_replay(request: ReplayRequest, state: StateDep) -> dict[str, Any]:
    """Start a synthetic or PCAP replay in the background.

    Replay is read-only with respect to the monitored network: it either reads a
    capture file or generates metadata locally. Nothing is transmitted.
    """
    if not state.settings.api.allow_replay_trigger:
        raise HTTPException(status_code=403, detail="replay triggering is disabled")
    if state.replay_status.get("state") == "running":
        raise HTTPException(status_code=409, detail="a replay is already running")

    from .sensor.replay import replay_pcap, replay_synthetic

    async def run() -> None:
        state.replay_status = {"state": "running", "scenario": request.scenario}
        try:
            summary = await asyncio.to_thread(
                replay_pcap if request.pcap else replay_synthetic,
                **(
                    {"pcap_path": request.pcap, "settings": state.settings}
                    if request.pcap
                    else {
                        "scenario": request.scenario,
                        "count": request.count,
                        "seed": request.seed,
                        "settings": state.settings,
                    }
                ),
            )
            state.replay_status = {"state": "completed", **summary}
        except Exception as exc:  # noqa: BLE001 -- surfaced through the status route
            state.replay_status = {"state": "failed", "error": str(exc)[:500]}

    asyncio.create_task(run())
    return {"accepted": True, "status_url": f"{PREFIX}/replay/status"}


@app.get(f"{PREFIX}/replay/status", tags=["replay"])
def replay_status(state: StateDep) -> dict[str, Any]:
    return state.replay_status


# --- websocket ------------------------------------------------------------
@app.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket) -> None:
    """Live alert feed, tailing the ``network.alerts`` Redis stream.

    Reading the stream (rather than having the pipeline push into a process-local
    queue) means the API and the detection worker stay independent processes: the
    worker can restart without dropping subscribers, and multiple API replicas each
    get the full feed.
    """
    await websocket.accept()
    state: AppState = websocket.app.dependency_overrides[get_state]()
    client = state.stream.raw
    last_id = "$"  # only alerts raised from now on
    try:
        await websocket.send_json({"type": "connected", "stream": Streams.ALERTS})
        while True:
            response = await asyncio.to_thread(
                client.xread, {Streams.ALERTS: last_id}, count=32, block=1000
            )
            if not response:
                # Keepalive: without it, an idle proxy closes the socket.
                await websocket.send_json({"type": "keepalive"})
                continue
            for _stream, entries in response:
                for message_id, fields in entries:
                    last_id = message_id
                    body = fields.get(PAYLOAD_FIELD)
                    if not body:
                        continue
                    try:
                        await websocket.send_json({"type": "alert", "alert": json.loads(body)})
                    except json.JSONDecodeError:
                        continue
    except WebSocketDisconnect:
        return
    except Exception as exc:  # noqa: BLE001
        log.warning("websocket closed", extra={"error": str(exc)[:200]})
        await websocket.close(code=1011)


def create_app() -> FastAPI:
    return app
