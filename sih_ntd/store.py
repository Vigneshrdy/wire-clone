"""Analytical store.

SQLite today, ClickHouse later, and this is the *only* module that knows SQL.
That is a deliberate trade: at prototype volume ClickHouse buys nothing but an
extra container and a dependency, and every table here is append-mostly with
simple time-ordered reads, which SQLite does well. Phase 12 replaces the bodies
of these methods; no caller changes.

Conventions
-----------
* Append-only where it is audit data: ``detector_results``, ``alert_events``,
  ``feedback``, ``drift_events``, ``benchmarks``. Alerts are the one mutable row
  (status, dedup counters), and every change to them is also written to
  ``alert_events`` so the decision history stays intact.
* No payload content is ever stored. PCAP files stay on disk; tables hold
  references.
* Evidence, lineage and feature maps are stored as JSON text: they are read whole,
  never filtered on, so columns would be pure overhead.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from .config import Settings, get_settings
from .schemas import (
    Alert,
    AlertStatus,
    AnalystFeedback,
    BenchmarkResult,
    DetectorResult,
    DriftEvent,
    FeatureVector,
    Incident,
    NormalizedEvent,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    ingest_ts REAL NOT NULL,
    sensor_id TEXT,
    source_type TEXT,
    flow_id TEXT,
    src_ip TEXT, src_port INTEGER,
    dst_ip TEXT, dst_port INTEGER,
    transport TEXT, service TEXT, direction TEXT,
    duration REAL,
    orig_packets INTEGER, resp_packets INTEGER,
    orig_bytes INTEGER, resp_bytes INTEGER,
    connection_state TEXT,
    dns_query TEXT, dns_qtype TEXT, dns_rcode TEXT,
    tls_ja4 TEXT, tls_sni TEXT, tls_version TEXT,
    pcap_reference TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip, ts);

CREATE TABLE IF NOT EXISTS features (
    ts REAL NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    window_seconds REAL NOT NULL,
    schema_version TEXT NOT NULL,
    values_json TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    event_count INTEGER
);
CREATE INDEX IF NOT EXISTS idx_features_entity ON features(entity_kind, entity_id, ts);

CREATE TABLE IF NOT EXISTS detector_results (
    ts REAL NOT NULL,
    detector_name TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    threat_class TEXT NOT NULL,
    technique TEXT NOT NULL,
    score REAL, confidence REAL, confidence_basis TEXT,
    severity_hint TEXT,
    entity_kind TEXT, entity_id TEXT, window_seconds REAL,
    src_ip TEXT, dst_ip TEXT,
    model_version TEXT, feature_schema_version TEXT,
    shadow INTEGER NOT NULL DEFAULT 0,
    supporting_json TEXT, reason_codes_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_ts ON detector_results(ts);
CREATE INDEX IF NOT EXISTS idx_results_detector ON detector_results(detector_name, ts);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    ts REAL NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    threat_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    confidence_basis TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT,
    entity_kind TEXT, entity_id TEXT,
    detector_name TEXT, detector_version TEXT, technique TEXT,
    model_version TEXT, feature_schema_version TEXT,
    correlation_id TEXT, incident_id TEXT,
    event_count INTEGER, dedup_count INTEGER,
    evidence_json TEXT NOT NULL,
    lineage_json TEXT NOT NULL,
    contributing_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_class ON alerts(threat_class, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);

CREATE TABLE IF NOT EXISTS alert_events (
    ts REAL NOT NULL,
    alert_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_events ON alert_events(alert_id, ts);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    created_at REAL, updated_at REAL,
    first_seen REAL, last_seen REAL,
    entity_kind TEXT, entity_id TEXT,
    primary_threat_class TEXT,
    threat_classes_json TEXT,
    severity TEXT, confidence REAL,
    alert_ids_json TEXT, alert_count INTEGER,
    summary TEXT, status TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(last_seen DESC);

CREATE TABLE IF NOT EXISTS feedback (
    feedback_id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    alert_id TEXT NOT NULL,
    label TEXT NOT NULL,
    corrected_threat_class TEXT,
    analyst_id TEXT,
    analyst_confidence REAL,
    notes TEXT,
    consumed_by_dataset TEXT
);
CREATE INDEX IF NOT EXISTS idx_feedback_alert ON feedback(alert_id);

CREATE TABLE IF NOT EXISTS drift_events (
    drift_id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    detector TEXT, model_version TEXT, feature TEXT,
    drift_type TEXT, metric TEXT,
    score REAL, threshold REAL, window TEXT,
    reference_size INTEGER, current_size INTEGER,
    recommendation TEXT
);
CREATE INDEX IF NOT EXISTS idx_drift_ts ON drift_events(ts DESC);

CREATE TABLE IF NOT EXISTS benchmarks (
    benchmark_id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    name TEXT,
    events INTEGER, duration_seconds REAL, events_per_second REAL,
    latency_p50_ms REAL, latency_p95_ms REAL, latency_p99_ms REAL, latency_max_ms REAL,
    stage_json TEXT, alerts_generated INTEGER,
    hardware TEXT, configuration_json TEXT, model_versions_json TEXT, dataset TEXT
);
CREATE INDEX IF NOT EXISTS idx_benchmarks_ts ON benchmarks(ts DESC);
"""


def _json(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


class Store:
    """Thin repository over SQLite. One connection per instance, not thread-shared."""

    def __init__(self, path: Path | str | None = None, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        raw_path = path if path is not None else self.settings.store.path
        self.path = Path(raw_path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # WAL lets the API read while the worker writes -- the whole point of
        # having a store rather than passing objects in memory.
        if str(self.path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(f"PRAGMA busy_timeout={self.settings.store.busy_timeout_ms}")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # --- writes ----------------------------------------------------------
    def insert_events(self, events: Iterable[NormalizedEvent]) -> int:
        rows = [
            (
                e.event_id, e.epoch, e.ingest_timestamp.timestamp(), e.sensor_id,
                str(e.source_type), e.flow_id, str(e.src_ip), e.src_port,
                str(e.dst_ip), e.dst_port, str(e.transport_protocol), e.service,
                str(e.direction), e.duration, e.orig_packets, e.resp_packets,
                e.orig_bytes, e.resp_bytes, e.connection_state,
                e.dns.query if e.dns else None,
                e.dns.qtype if e.dns else None,
                e.dns.rcode if e.dns else None,
                e.tls.ja4 if e.tls else None,
                e.tls.sni if e.tls else None,
                e.tls.version if e.tls else None,
                e.pcap_reference,
            )
            for e in events
        ]
        if not rows:
            return 0
        with self._tx() as conn:
            # INSERT OR IGNORE gives idempotent replay: the same PCAP twice does
            # not duplicate rows, because event_id is derived deterministically.
            # rowcount is the number actually inserted, so a caller can see how
            # many were duplicates.
            cursor = conn.executemany(
                "INSERT OR IGNORE INTO events VALUES (" + ",".join("?" * 26) + ")", rows
            )
        return cursor.rowcount or 0

    def insert_features(self, vectors: Iterable[FeatureVector]) -> int:
        if not self.settings.store.persist_features:
            return 0
        rows = [
            (
                v.timestamp.timestamp(), str(v.entity_kind), v.entity_id, v.window_seconds,
                v.schema_version, _json(v.values), _json(v.labels), v.event_count,
            )
            for v in vectors
        ]
        if not rows:
            return 0
        with self._tx() as conn:
            conn.executemany("INSERT INTO features VALUES (?,?,?,?,?,?,?,?)", rows)
        return len(rows)

    def insert_detector_results(self, results: Iterable[DetectorResult]) -> int:
        rows = [
            (
                r.timestamp.timestamp(), r.detector_name, r.detector_version,
                str(r.threat_class), str(r.technique), r.score, r.confidence,
                str(r.confidence_basis), str(r.severity_hint), str(r.entity_kind),
                r.entity_id, r.window_seconds, r.src_ip, r.dst_ip, r.model_version,
                r.feature_schema_version, 1 if r.shadow else 0,
                _json(r.supporting_features), _json(r.reason_codes),
            )
            for r in results
        ]
        if not rows:
            return 0
        with self._tx() as conn:
            conn.executemany(
                "INSERT INTO detector_results VALUES (" + ",".join("?" * 19) + ")", rows
            )
        return len(rows)

    def insert_alerts(self, alerts: Iterable[Alert]) -> int:
        alerts = list(alerts)
        if not alerts:
            return 0
        rows = [
            (
                a.alert_id, a.schema_version, a.timestamp.timestamp(),
                a.first_seen.timestamp(), a.last_seen.timestamp(), str(a.threat_class),
                a.confidence, str(a.confidence_basis), str(a.severity), str(a.status),
                a.src_ip, a.dst_ip, str(a.entity_kind), a.entity_id, a.detector_name,
                a.detector_version, str(a.technique), a.model_version,
                a.feature_schema_version, a.correlation_id, a.incident_id,
                a.event_count, a.dedup_count,
                a.evidence.model_dump_json(), a.lineage.model_dump_json(),
                _json(a.contributing_detectors),
            )
            for a in alerts
        ]
        with self._tx() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO alerts VALUES (" + ",".join("?" * 26) + ")", rows
            )
            conn.executemany(
                "INSERT INTO alert_events VALUES (?,?,?,?)",
                [
                    (a.timestamp.timestamp(), a.alert_id, "CREATED",
                     _json({"threat_class": str(a.threat_class), "severity": str(a.severity),
                            "confidence": a.confidence}))
                    for a in alerts
                ],
            )
        return len(rows)

    def touch_alert(self, alert_id: str, last_seen: float, dedup_count: int, event_count: int) -> None:
        """Advance a suppressed duplicate's counters, keeping the audit trail."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE alerts SET last_seen=?, dedup_count=?, event_count=? WHERE alert_id=?",
                (last_seen, dedup_count, event_count, alert_id),
            )
            conn.execute(
                "INSERT INTO alert_events VALUES (?,?,?,?)",
                (last_seen, alert_id, "DEDUPED", _json({"dedup_count": dedup_count})),
            )

    def set_alert_status(self, alert_id: str, status: AlertStatus, actor: str = "api") -> bool:
        with self._tx() as conn:
            cursor = conn.execute(
                "UPDATE alerts SET status=? WHERE alert_id=?", (str(status), alert_id)
            )
            if cursor.rowcount:
                conn.execute(
                    "INSERT INTO alert_events VALUES (?,?,?,?)",
                    (0.0, alert_id, "STATUS", _json({"status": str(status), "actor": actor})),
                )
            return bool(cursor.rowcount)

    def upsert_incidents(self, incidents: Iterable[Incident]) -> int:
        rows = [
            (
                i.incident_id, i.created_at.timestamp(), i.updated_at.timestamp(),
                i.first_seen.timestamp(), i.last_seen.timestamp(), str(i.entity_kind),
                i.entity_id, str(i.primary_threat_class),
                _json([str(c) for c in i.threat_classes]), str(i.severity), i.confidence,
                _json(i.alert_ids), i.alert_count, i.summary, str(i.status),
            )
            for i in incidents
        ]
        if not rows:
            return 0
        with self._tx() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO incidents VALUES (" + ",".join("?" * 15) + ")", rows
            )
        return len(rows)

    def insert_feedback(self, feedback: AnalystFeedback) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO feedback VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    feedback.feedback_id, feedback.timestamp.timestamp(), feedback.alert_id,
                    str(feedback.label),
                    str(feedback.corrected_threat_class) if feedback.corrected_threat_class else None,
                    feedback.analyst_id, feedback.analyst_confidence, feedback.notes, None,
                ),
            )

    def insert_drift_events(self, events: Iterable[DriftEvent]) -> int:
        rows = [
            (
                d.drift_id, d.timestamp.timestamp(), d.detector, d.model_version, d.feature,
                str(d.drift_type), d.metric, d.score, d.threshold, d.window,
                d.reference_size, d.current_size, d.recommendation,
            )
            for d in events
        ]
        if not rows:
            return 0
        with self._tx() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO drift_events VALUES (" + ",".join("?" * 13) + ")", rows
            )
        return len(rows)

    def insert_benchmark(self, result: BenchmarkResult) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO benchmarks VALUES (" + ",".join("?" * 16) + ")",
                (
                    result.benchmark_id, result.timestamp.timestamp(), result.name,
                    result.events, result.duration_seconds, result.events_per_second,
                    result.latency_p50_ms, result.latency_p95_ms, result.latency_p99_ms,
                    result.latency_max_ms, _json(result.stage_seconds),
                    result.alerts_generated, result.hardware, _json(result.configuration),
                    _json(result.model_versions), result.dataset,
                ),
            )

    # --- reads -----------------------------------------------------------
    @staticmethod
    def _alert_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "alert_id": row["alert_id"],
            "schema_version": row["schema_version"],
            "timestamp": row["ts"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "threat_class": row["threat_class"],
            "confidence": row["confidence"],
            "confidence_basis": row["confidence_basis"],
            "severity": row["severity"],
            "status": row["status"],
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "entity_kind": row["entity_kind"],
            "entity_id": row["entity_id"],
            "detector_name": row["detector_name"],
            "detector_version": row["detector_version"],
            "technique": row["technique"],
            "model_version": row["model_version"],
            "feature_schema_version": row["feature_schema_version"],
            "correlation_id": row["correlation_id"],
            "incident_id": row["incident_id"],
            "event_count": row["event_count"],
            "dedup_count": row["dedup_count"],
            "evidence": json.loads(row["evidence_json"]),
            "lineage": json.loads(row["lineage_json"]),
            "contributing_detectors": json.loads(row["contributing_json"]),
        }

    def query_alerts(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        threat_class: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        src_ip: str | None = None,
        since: float | None = None,
        until: float | None = None,
        min_confidence: float | None = None,
        incident_id: str | None = None,
    ) -> list[Alert]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("threat_class", threat_class), ("severity", severity), ("status", status),
            ("src_ip", src_ip), ("incident_id", incident_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until)
        if min_confidence is not None:
            clauses.append("confidence >= ?")
            params.append(min_confidence)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        rows = self._conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY ts DESC LIMIT ? OFFSET ?", params
        ).fetchall()
        return [Alert.model_validate(self._alert_from_row(row)) for row in rows]

    def get_alert(self, alert_id: str) -> Alert | None:
        row = self._conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return Alert.model_validate(self._alert_from_row(row)) if row else None

    def alert_history(self, alert_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT ts, kind, detail_json FROM alert_events WHERE alert_id = ? ORDER BY ts",
            (alert_id,),
        ).fetchall()
        return [
            {"timestamp": r["ts"], "kind": r["kind"], "detail": json.loads(r["detail_json"] or "{}")}
            for r in rows
        ]

    def count_alerts(self, **filters: Any) -> int:
        clauses, params = [], []
        for column, value in filters.items():
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return int(self._conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0])

    def alert_summary(self) -> dict[str, dict[str, int]]:
        by_class = {
            r["threat_class"]: r["n"]
            for r in self._conn.execute(
                "SELECT threat_class, COUNT(*) AS n FROM alerts GROUP BY threat_class"
            )
        }
        by_severity = {
            r["severity"]: r["n"]
            for r in self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
            )
        }
        return {"by_threat_class": by_class, "by_severity": by_severity}

    def query_incidents(self, *, limit: int = 50, offset: int = 0) -> list[Incident]:
        rows = self._conn.execute(
            "SELECT * FROM incidents ORDER BY last_seen DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        return [self._incident_from_row(r) for r in rows]

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self._conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        return self._incident_from_row(row) if row else None

    @staticmethod
    def _incident_from_row(row: sqlite3.Row) -> Incident:
        return Incident.model_validate(
            {
                "incident_id": row["incident_id"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "entity_kind": row["entity_kind"],
                "entity_id": row["entity_id"],
                "primary_threat_class": row["primary_threat_class"],
                "threat_classes": json.loads(row["threat_classes_json"]),
                "severity": row["severity"],
                "confidence": row["confidence"],
                "alert_ids": json.loads(row["alert_ids_json"]),
                "alert_count": row["alert_count"],
                "summary": row["summary"],
                "status": row["status"],
            }
        )

    def query_flows(
        self, *, limit: int = 50, offset: int = 0, src_ip: str | None = None,
        dst_ip: str | None = None, since: float | None = None,
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        for column, value in (("src_ip", src_ip), ("dst_ip", dst_ip)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        rows = self._conn.execute(
            f"SELECT * FROM events {where} ORDER BY ts DESC LIMIT ? OFFSET ?", params
        ).fetchall()
        return [dict(r) for r in rows]

    def query_drift(self, *, limit: int = 50, detector: str | None = None) -> list[DriftEvent]:
        where, params = ("WHERE detector = ?", [detector]) if detector else ("", [])
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT * FROM drift_events {where} ORDER BY ts DESC LIMIT ?", params
        ).fetchall()
        return [
            DriftEvent.model_validate(
                {
                    "drift_id": r["drift_id"], "timestamp": r["ts"], "detector": r["detector"],
                    "model_version": r["model_version"], "feature": r["feature"],
                    "drift_type": r["drift_type"], "metric": r["metric"], "score": r["score"],
                    "threshold": r["threshold"], "window": r["window"],
                    "reference_size": r["reference_size"], "current_size": r["current_size"],
                    "recommendation": r["recommendation"],
                }
            )
            for r in rows
        ]

    def query_benchmarks(self, *, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM benchmarks ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for r in rows:
            row = dict(r)
            for key in ("stage_json", "configuration_json", "model_versions_json"):
                row[key.removesuffix("_json")] = json.loads(row.pop(key) or "{}")
            out.append(row)
        return out

    def query_feedback(self, *, limit: int = 200, unconsumed_only: bool = False) -> list[dict[str, Any]]:
        where = "WHERE consumed_by_dataset IS NULL" if unconsumed_only else ""
        rows = self._conn.execute(
            f"SELECT * FROM feedback {where} ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_feedback_consumed(self, feedback_ids: list[str], dataset_id: str) -> int:
        if not feedback_ids:
            return 0
        with self._tx() as conn:
            cursor = conn.executemany(
                "UPDATE feedback SET consumed_by_dataset = ? WHERE feedback_id = ?",
                [(dataset_id, fid) for fid in feedback_ids],
            )
            return cursor.rowcount or 0

    def feature_rows(
        self, *, entity_kind: str | None = None, window_seconds: float | None = None,
        limit: int = 100_000,
    ) -> list[dict[str, Any]]:
        """Historical feature vectors, for the training data factory and drift."""
        clauses, params = [], []
        if entity_kind:
            clauses.append("entity_kind = ?")
            params.append(entity_kind)
        if window_seconds is not None:
            clauses.append("window_seconds = ?")
            params.append(window_seconds)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT * FROM features {where} ORDER BY ts DESC LIMIT ?", params
        ).fetchall()
        return [
            {
                "timestamp": r["ts"], "entity_kind": r["entity_kind"], "entity_id": r["entity_id"],
                "window_seconds": r["window_seconds"], "schema_version": r["schema_version"],
                "values": json.loads(r["values_json"]), "labels": json.loads(r["labels_json"]),
                "event_count": r["event_count"],
            }
            for r in rows
        ]

    def detector_result_scores(
        self, detector: str, *, shadow: bool | None = None, limit: int = 10_000
    ) -> list[float]:
        """Confidence values for drift monitoring."""
        clauses = ["detector_name = ?"]
        params: list[Any] = [detector]
        if shadow is not None:
            clauses.append("shadow = ?")
            params.append(1 if shadow else 0)
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT confidence FROM detector_results WHERE {' AND '.join(clauses)} "
            "ORDER BY ts DESC LIMIT ?",
            params,
        ).fetchall()
        return [float(r["confidence"]) for r in rows]

    def health(self) -> dict[str, Any]:
        tables = ("events", "features", "detector_results", "alerts", "incidents",
                  "feedback", "drift_events", "benchmarks")
        return {
            "path": str(self.path),
            "counts": {
                table: int(self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in tables
            },
        }

    def prune(self, older_than_epoch: float) -> dict[str, int]:
        """Retention. Alerts and incidents are kept; raw telemetry is not."""
        deleted: dict[str, int] = {}
        with self._tx() as conn:
            for table in ("events", "features", "detector_results"):
                cursor = conn.execute(f"DELETE FROM {table} WHERE ts < ?", (older_than_epoch,))
                deleted[table] = cursor.rowcount or 0
        return deleted
