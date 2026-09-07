"""Threat fusion: correlation, duplicate suppression, severity, incidents.

Detector results are immutable. Fusion never edits them; it reads them and
produces new records (:class:`~sih_ntd.schemas.Alert`,
:class:`~sih_ntd.schemas.Incident`).

Three jobs, in order:

1. **Duplicate suppression.** A flood produces one detector result per emit tick.
   The first becomes an alert; the rest bump that alert's ``dedup_count`` and
   ``last_seen`` instead of creating hundreds of rows.
2. **Cross-detector correlation.** Results about the same subject inside
   ``correlation_window_seconds`` corroborate each other. A DGA hit plus a beacon
   to a rare destination is a stronger story than either alone, and the confidence
   uplift is a documented, bounded formula -- not a guess.
3. **Incident grouping.** Two or more *distinct* threat classes on one subject
   become an incident, which is what an analyst actually triages.

Confidence combination
----------------------
::

    combined = min(max_confidence, primary_confidence + bonus * distinct_corroborators)

with ``bonus = fusion.corroboration_bonus`` (default 0.08) and
``max_confidence = 0.99``. Bounded, monotonic, reproducible from the stored
detector contributions. Severity is computed separately -- see :func:`score_severity`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .config import Settings, get_settings
from .evidence import build_evidence, build_lineage, subject_of
from .metrics import ALERTS_SUPPRESSED, ALERTS_TOTAL
from .schemas import (
    SEVERITY_ORDER,
    Alert,
    ConfidenceBasis,
    DetectorResult,
    EntityKind,
    Incident,
    Severity,
    ThreatClass,
)
from .windows import LruStateMap

_SEVERITY_LADDER = [
    Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL
]

#: Threat classes whose successful execution implies an already-compromised host,
#: so their floor severity is higher regardless of detector confidence.
_IMPACT_FLOOR: dict[ThreatClass, Severity] = {
    ThreatClass.C2_BEACON: Severity.MEDIUM,
    ThreatClass.EXFILTRATION: Severity.MEDIUM,
    ThreatClass.DNS_TUNNEL: Severity.MEDIUM,
}


def score_severity(
    threat_class: ThreatClass,
    detector_hint: Severity,
    corroborators: int,
    confidence: float,
) -> Severity:
    """Potential impact, deliberately not a restatement of confidence.

    Starts from the detector's own impact assessment (it knows the volumes),
    applies a per-class floor for threats that imply compromise, and escalates one
    step when at least two other detectors independently agree -- a corroborated
    threat has more of the estate involved, which is an impact statement rather
    than a certainty one. High confidence with a single weak signal does *not*
    escalate.
    """
    severity = detector_hint
    floor = _IMPACT_FLOOR.get(threat_class)
    if floor is not None and SEVERITY_ORDER[severity] < SEVERITY_ORDER[floor]:
        severity = floor
    if corroborators >= 2:
        index = min(len(_SEVERITY_LADDER) - 1, _SEVERITY_LADDER.index(severity) + 1)
        severity = _SEVERITY_LADDER[index]
    return severity


@dataclass
class AlertTouch:
    """An alert that already exists and just needs its counters advanced."""

    alert_id: str
    last_seen: float
    dedup_count: int
    event_count: int


@dataclass
class FusionOutcome:
    alerts: list[Alert] = field(default_factory=list)
    touches: list[AlertTouch] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)


@dataclass
class _DedupEntry:
    alert_id: str
    first_seen: float
    last_seen: float
    count: int
    event_count: int


@dataclass
class _Subject:
    """Recent detector activity for one subject (host, pair or destination)."""

    results: list[DetectorResult] = field(default_factory=list)
    incident_id: str | None = None
    alert_ids: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0

    def prune(self, cutoff: float) -> None:
        self.results = [r for r in self.results if r.timestamp.timestamp() >= cutoff]


class ThreatFusion:
    """Stateful fusion layer. One instance per pipeline worker."""

    def __init__(self, settings: Settings | None = None, pipeline_run_id: str | None = None) -> None:
        self.settings = settings or get_settings()
        self.config = self.settings.fusion
        self.pipeline_run_id = pipeline_run_id
        capacity = self.settings.windows.max_tracked_entities
        self._dedup: LruStateMap = LruStateMap(capacity)
        self._subjects: LruStateMap = LruStateMap(capacity)

    # --- subject keying ---------------------------------------------------
    #: Subject selection lives in :func:`sih_ntd.evidence.subject_of` so alert
    #: wording and incident grouping can never disagree about whose alert it is.
    subject_of = staticmethod(subject_of)

    def ingest(self, results: list[DetectorResult]) -> FusionOutcome:
        """Fuse a batch of detector results into alerts, touches and incidents."""
        outcome = FusionOutcome()
        for result in results:
            if result.shadow:
                # Challenger output is recorded elsewhere and must never alert.
                continue
            self._fuse_one(result, outcome)
        return outcome

    def _fuse_one(self, result: DetectorResult, outcome: FusionOutcome) -> None:
        ts = result.timestamp.timestamp()
        subject_id = self.subject_of(result)
        subject = self._subjects.touch(subject_id, lambda: _Subject(first_seen=ts))
        subject.prune(ts - self.config.correlation_window_seconds)
        if subject.last_seen and ts - subject.last_seen > self.config.incident_idle_seconds:
            subject.incident_id = None
            subject.alert_ids = []
            subject.first_seen = ts

        corroborating = [
            r
            for r in subject.results
            if r.threat_class is not result.threat_class
            and r.detector_name != result.detector_name
        ]
        distinct = len({r.detector_name for r in corroborating})

        confidence = min(
            self.config.max_confidence,
            result.confidence + self.config.corroboration_bonus * distinct,
        )
        subject.results.append(result)
        subject.last_seen = ts

        if confidence < self.config.min_alert_confidence:
            return

        key = (result.detector_name, str(result.threat_class), result.entity_id)
        existing = self._dedup.get(key)
        if existing is not None and ts - existing.last_seen <= self.config.dedup_window_seconds:
            existing.last_seen = ts
            existing.count += 1
            existing.event_count += 1
            ALERTS_SUPPRESSED.inc(threat_class=str(result.threat_class))
            outcome.touches.append(
                AlertTouch(
                    alert_id=existing.alert_id,
                    last_seen=ts,
                    dedup_count=existing.count,
                    event_count=existing.event_count,
                )
            )
            return

        severity = score_severity(result.threat_class, result.severity_hint, distinct, confidence)
        alert = Alert(
            alert_id=self._alert_id(result, ts),
            timestamp=ts,
            first_seen=ts,
            last_seen=ts,
            threat_class=result.threat_class,
            confidence=confidence,
            confidence_basis=(
                ConfidenceBasis.FUSION if distinct else result.confidence_basis
            ),
            severity=severity,
            src_ip=result.src_ip,
            dst_ip=result.dst_ip,
            entity_kind=result.entity_kind,
            entity_id=result.entity_id,
            detector_name=result.detector_name,
            detector_version=result.detector_version,
            technique=result.technique,
            model_version=result.model_version,
            feature_schema_version=result.feature_schema_version,
            correlation_id=subject_id,
            event_count=1,
            evidence=build_evidence(result, corroborating),
            lineage=build_lineage(result, corroborating, self.pipeline_run_id),
            contributing_detectors=sorted({r.detector_name for r in corroborating}),
        )
        self._dedup.touch(
            key,
            lambda: _DedupEntry(
                alert_id=alert.alert_id, first_seen=ts, last_seen=ts, count=1, event_count=1
            ),
        )
        subject.alert_ids.append(alert.alert_id)
        ALERTS_TOTAL.inc(threat_class=str(alert.threat_class), severity=str(alert.severity))

        incident = self._update_incident(subject_id, subject, alert, ts)
        if incident is not None:
            alert = alert.model_copy(update={"incident_id": incident.incident_id})
            outcome.incidents.append(incident)
        outcome.alerts.append(alert)

    def _alert_id(self, result: DetectorResult, ts: float) -> str:
        bucket = int(ts // self.config.dedup_window_seconds)
        material = "|".join(
            [result.detector_name, str(result.threat_class), result.entity_id, str(bucket)]
        )
        return hashlib.sha256(material.encode()).hexdigest()[:32]

    def _update_incident(
        self, subject_id: str, subject: _Subject, alert: Alert, ts: float
    ) -> Incident | None:
        """Create or extend an incident once a subject shows 2+ threat classes.

        A single threat class is an alert; two different ones on the same asset is
        a story, and that is what deserves a triage object.
        """
        classes = sorted({str(r.threat_class) for r in subject.results})
        if len(classes) < 2:
            return None
        primary = max(
            subject.results,
            key=lambda r: (SEVERITY_ORDER[r.severity_hint], r.confidence),
        )
        incident = Incident(
            incident_id=subject.incident_id or Incident(
                first_seen=ts, last_seen=ts, entity_kind=alert.entity_kind,
                entity_id=subject_id, primary_threat_class=alert.threat_class,
                severity=alert.severity, confidence=alert.confidence,
            ).incident_id,
            first_seen=min(subject.first_seen or ts, ts),
            last_seen=ts,
            entity_kind=alert.entity_kind,
            entity_id=subject_id,
            primary_threat_class=primary.threat_class,
            threat_classes=[ThreatClass(c) for c in classes],
            severity=alert.severity,
            confidence=alert.confidence,
            alert_ids=subject.alert_ids[-512:],
            alert_count=len(subject.alert_ids),
            summary=(
                f"{subject_id}: {len(classes)} correlated threat classes "
                f"({', '.join(classes)}) within "
                f"{int(self.config.correlation_window_seconds)}s"
            ),
        )
        subject.incident_id = incident.incident_id
        return incident

    def expire(self, now: float) -> None:
        """Drop state for subjects and dedup keys that have gone quiet."""
        dedup_cutoff = now - self.config.dedup_window_seconds
        retained_dedup = LruStateMap(self.settings.windows.max_tracked_entities)
        for key, value in self._dedup.items():
            if value.last_seen >= dedup_cutoff:
                retained_dedup[key] = value
        self._dedup = retained_dedup
        subject_cutoff = now - self.config.incident_idle_seconds
        retained_subjects = LruStateMap(self.settings.windows.max_tracked_entities)
        for key, value in self._subjects.items():
            if value.last_seen >= subject_cutoff:
                retained_subjects[key] = value
        self._subjects = retained_subjects

    @property
    def tracked_subjects(self) -> int:
        return len(self._subjects)

    @property
    def tracked_dedup_keys(self) -> int:
        return len(self._dedup)
