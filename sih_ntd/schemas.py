"""Versioned, validated schemas for every artefact that crosses a module boundary.

Everything in here is a trust boundary: normalized events are built from captured
network metadata, feedback comes from an operator, threat intel comes from the
outside world. Field types are deliberately tight (length caps, charset checks,
range checks) so malformed or hostile input is rejected at parse time rather than
somewhere deep in a detector.

Schema versions are explicit and separate:

* ``EVENT_SCHEMA_VERSION``   -- shape of :class:`NormalizedEvent`
* ``FEATURE_SCHEMA_VERSION`` -- shape/semantics of :class:`FeatureVector`
* ``ALERT_SCHEMA_VERSION``   -- shape of :class:`Alert`

Bumping ``FEATURE_SCHEMA_VERSION`` invalidates every trained model: the registry
refuses to serve a model whose recorded feature schema differs from the running
one (see :mod:`sih_ntd.ml.registry`).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
    field_validator,
    model_validator,
)

EVENT_SCHEMA_VERSION = "1.0.0"
FEATURE_SCHEMA_VERSION = "1.0.0"
ALERT_SCHEMA_VERSION = "1.0.0"

# Length caps for untrusted strings. A DNS name cannot legally exceed 253
# characters; anything longer is either broken or an attempt to blow up a buffer
# or a log line, and is rejected rather than truncated.
MAX_DOMAIN_LEN = 253
MAX_LABEL_LEN = 63
MAX_SHORT_TEXT = 256
MAX_NOTE_LEN = 4096

ShortText = Annotated[str, StringConstraints(max_length=MAX_SHORT_TEXT, strip_whitespace=True)]
Note = Annotated[str, StringConstraints(max_length=MAX_NOTE_LEN)]
Port = Annotated[int, Field(ge=0, le=65535)]
NonNegInt = Annotated[int, Field(ge=0)]
NonNegFloat = Annotated[float, Field(ge=0.0)]
UnitFloat = Annotated[float, Field(ge=0.0, le=1.0)]
SemVer = Annotated[str, StringConstraints(pattern=r"^\d+\.\d+\.\d+$")]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class SourceType(StrEnum):
    """Where an event came from. Never used to grant trust, only for provenance."""

    LIVE_TAP = "LIVE_TAP"
    SPAN = "SPAN"
    DIODE = "DIODE"
    PCAP_REPLAY = "PCAP_REPLAY"
    ZEEK_LOG = "ZEEK_LOG"
    NETFLOW = "NETFLOW"
    IPFIX = "IPFIX"
    SFLOW = "SFLOW"
    SYNTHETIC = "SYNTHETIC"


class TransportProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class Direction(StrEnum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"
    UNKNOWN = "UNKNOWN"


class ThreatClass(StrEnum):
    BENIGN = "BENIGN"
    DDOS = "DDOS"
    C2_BEACON = "C2_BEACON"
    DGA = "DGA"
    DNS_TUNNEL = "DNS_TUNNEL"
    TLS_MALWARE = "TLS_MALWARE"
    RECON = "RECON"
    EXFILTRATION = "EXFILTRATION"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class DetectorState(StrEnum):
    """Runtime availability of a detector.

    ``UNAVAILABLE`` is an honest answer, not a failure: it means the detector
    needs an artefact (trained model, fingerprint corpus) that is not present.
    """

    READY = "READY"
    UNAVAILABLE = "UNAVAILABLE"
    DISABLED = "DISABLED"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


class Technique(StrEnum):
    """How a verdict was produced. Recorded so alerts never overstate "AI"."""

    RULE = "RULE"
    STATISTICAL = "STATISTICAL"
    SUPERVISED = "SUPERVISED"
    HYBRID = "HYBRID"


class ConfidenceBasis(StrEnum):
    """How ``confidence`` was computed, so it is reproducible after the fact."""

    RULE_EVIDENCE = "RULE_EVIDENCE"
    NORMALISED_ANOMALY = "NORMALISED_ANOMALY"
    CALIBRATED_PROBABILITY = "CALIBRATED_PROBABILITY"
    FUSION = "FUSION"


class AlertStatus(StrEnum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"
    SUPPRESSED = "SUPPRESSED"


class FeedbackLabel(StrEnum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
    UNCERTAIN = "UNCERTAIN"


class ModelStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    CHALLENGER = "CHALLENGER"
    CHAMPION = "CHAMPION"
    RETIRED = "RETIRED"
    REJECTED = "REJECTED"


class DriftType(StrEnum):
    FEATURE_DISTRIBUTION = "FEATURE_DISTRIBUTION"
    PREDICTION_DISTRIBUTION = "PREDICTION_DISTRIBUTION"
    CONFIDENCE_DISTRIBUTION = "CONFIDENCE_DISTRIBUTION"
    CLASS_DISTRIBUTION = "CLASS_DISTRIBUTION"
    LABEL_PERFORMANCE = "LABEL_PERFORMANCE"


class EntityKind(StrEnum):
    """Scope of a behavioural baseline."""

    HOST = "HOST"
    SUBNET = "SUBNET"
    DESTINATION = "DESTINATION"
    SERVICE = "SERVICE"
    PROTOCOL = "PROTOCOL"
    PAIR = "PAIR"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc(value: Any) -> Any:
    """Accept epoch seconds (Zeek/NetFlow style) or datetimes; always emit UTC."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return value


def normalise_domain(raw: str) -> str:
    """Validate and canonicalise an untrusted DNS name.

    Rejects over-long names/labels and anything outside the LDH charset plus
    ``_`` (service labels) and ``*`` (wildcards seen in certificates). Returns
    the lowercase form with a trailing dot stripped.
    """
    name = raw.strip().rstrip(".").lower()
    if not name:
        raise ValueError("empty domain")
    if len(name) > MAX_DOMAIN_LEN:
        raise ValueError(f"domain longer than {MAX_DOMAIN_LEN} characters")
    labels = name.split(".")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_*")
    for label in labels:
        if not label:
            raise ValueError("empty DNS label")
        if len(label) > MAX_LABEL_LEN:
            raise ValueError(f"DNS label longer than {MAX_LABEL_LEN} characters")
        if not set(label) <= allowed:
            raise ValueError("DNS label contains characters outside LDH")
    return name


class Strict(BaseModel):
    """Base for everything: unknown fields are an error, not silent data loss."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Frozen(Strict):
    """Immutable records. Detector output and alerts must never be edited in place."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DnsMetadata(Strict):
    """DNS metadata only -- question/answer names and counts, never payload bytes."""

    query: str | None = None
    qtype: ShortText | None = None
    rcode: ShortText | None = None
    answers: list[ShortText] = Field(default_factory=list, max_length=64)
    response_bytes: NonNegInt | None = None
    rejected: bool = False

    @field_validator("query")
    @classmethod
    def _check_query(cls, v: str | None) -> str | None:
        return None if v is None else normalise_domain(v)

    @property
    def query_length(self) -> int:
        return len(self.query or "")

    @property
    def labels(self) -> list[str]:
        return (self.query or "").split(".") if self.query else []

    @property
    def subdomain_depth(self) -> int:
        """Label count excluding the registrable part (approximated as last two)."""
        return max(0, len(self.labels) - 2)

    @property
    def answer_count(self) -> int:
        return len(self.answers)


class TlsMetadata(Strict):
    """TLS/QUIC handshake metadata. No decryption, ever -- see docs/SECURITY_MODEL.md."""

    version: ShortText | None = None
    sni: str | None = None
    ja4: ShortText | None = None
    ja4s: ShortText | None = None
    cipher: ShortText | None = None
    cert_subject_cn: ShortText | None = None
    cert_issuer_cn: ShortText | None = None
    cert_validity_days: NonNegInt | None = None
    cert_self_signed: bool | None = None
    established: bool | None = None

    @field_validator("sni")
    @classmethod
    def _check_sni(cls, v: str | None) -> str | None:
        return None if v is None else normalise_domain(v)


class NormalizedEvent(Frozen):
    """Canonical flow/protocol event -- the only thing the pipeline consumes.

    One event is one observed flow (plus optional protocol metadata), which is
    what a passive sensor can actually see on a mirrored or unidirectional link.
    ``resp_*`` fields are optional precisely because on a truly unidirectional
    tap the reverse direction may be invisible; detectors must not assume they
    are present.
    """

    schema_version: SemVer = EVENT_SCHEMA_VERSION
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime
    ingest_timestamp: datetime = Field(default_factory=utcnow)

    sensor_id: ShortText = "unknown-sensor"
    source_type: SourceType

    flow_id: ShortText | None = None
    src_ip: IPvAnyAddress
    src_port: Port | None = None
    dst_ip: IPvAnyAddress
    dst_port: Port | None = None
    ip_version: Literal[4, 6] = 4
    transport_protocol: TransportProtocol
    service: ShortText | None = None
    direction: Direction = Direction.UNKNOWN

    duration: NonNegFloat | None = None
    orig_packets: NonNegInt = 0
    resp_packets: NonNegInt | None = None
    orig_bytes: NonNegInt = 0
    resp_bytes: NonNegInt | None = None
    connection_state: ShortText | None = None
    tcp_flags: ShortText | None = None

    dns: DnsMetadata | None = None
    tls: TlsMetadata | None = None

    pcap_reference: ShortText | None = None
    raw_event_reference: ShortText | None = None

    _validate_ts = field_validator("timestamp", "ingest_timestamp", mode="before")(_to_utc)

    @field_validator("schema_version")
    @classmethod
    def _known_version(cls, v: str) -> str:
        if v != EVENT_SCHEMA_VERSION:
            raise ValueError(f"unsupported event schema_version {v!r}; this build speaks {EVENT_SCHEMA_VERSION}")
        return v

    @model_validator(mode="after")
    def _derive(self) -> "NormalizedEvent":
        # ip_version must agree with the addresses; flow_id is derived when the
        # sensor did not supply one so correlation still works.
        version = self.src_ip.version
        if version != self.dst_ip.version:
            raise ValueError("src_ip and dst_ip have different IP versions")
        if self.ip_version != version:
            object.__setattr__(self, "ip_version", version)
        if self.flow_id is None:
            object.__setattr__(self, "flow_id", self.derive_flow_id())
        return self

    def derive_flow_id(self) -> str:
        """Stable 5-tuple hash. Direction-preserving: A->B and B->A differ."""
        key = f"{self.src_ip}|{self.src_port}|{self.dst_ip}|{self.dst_port}|{self.transport_protocol}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def epoch(self) -> float:
        return self.timestamp.timestamp()

    @property
    def total_bytes(self) -> int:
        return self.orig_bytes + (self.resp_bytes or 0)

    @property
    def total_packets(self) -> int:
        return self.orig_packets + (self.resp_packets or 0)

    @property
    def is_syn_only(self) -> bool:
        """TCP flow that was never established -- flood/scan evidence.

        Zeek conn states: S0 (SYN, no reply), REJ (rejected), S1/SF are real
        connections. History string 'S' with no 'h' (SYN-ACK) means the same.
        """
        if self.transport_protocol is not TransportProtocol.TCP:
            return False
        if self.connection_state in {"S0", "REJ", "RSTOS0", "SH", "SHR"}:
            return True
        if self.tcp_flags and "S" in self.tcp_flags.upper():
            return not (self.resp_packets or 0)
        return False

    @property
    def failed(self) -> bool:
        """Connection attempt that produced no response at all."""
        if self.connection_state in {"S0", "REJ", "RSTOS0", "SH"}:
            return True
        return (self.resp_packets or 0) == 0 and (self.resp_bytes or 0) == 0


class FeatureVector(Frozen):
    """Features for one (entity, window) observation.

    ``values`` is a flat ``name -> float`` map rather than a fixed field list so a
    detector can request exactly the features it needs and the training pipeline
    can serialise the same map to a dataset row. The trade-off is that the
    contract lives in ``FEATURE_SCHEMA_VERSION`` plus
    :data:`sih_ntd.features.engine.FEATURE_NAMES` instead of in the type system;
    :func:`require` makes a missing feature a loud error rather than a zero.
    """

    schema_version: SemVer = FEATURE_SCHEMA_VERSION
    timestamp: datetime
    entity_kind: EntityKind
    entity_id: ShortText
    window_seconds: NonNegFloat
    values: dict[str, float] = Field(default_factory=dict)
    # Non-numeric context a detector needs for evidence (the queried domain, a
    # JA4 hash, the SNI). Kept out of `values` so the numeric vector stays a
    # clean model input, and length-capped because it is attacker-controlled.
    labels: dict[str, ShortText] = Field(default_factory=dict)
    # Provenance for evidence + PCAP pivoting; capped so a burst cannot blow up memory.
    event_count: NonNegInt = 0
    flow_ids: list[ShortText] = Field(default_factory=list, max_length=64)
    pcap_references: list[ShortText] = Field(default_factory=list, max_length=8)

    _validate_ts = field_validator("timestamp", mode="before")(_to_utc)

    @field_validator("values")
    @classmethod
    def _finite(cls, v: dict[str, float]) -> dict[str, float]:
        for name, value in v.items():
            f = float(value)
            if f != f or f in (float("inf"), float("-inf")):
                raise ValueError(f"feature {name!r} is not finite ({value!r})")
        return {k: float(x) for k, x in v.items()}

    def get(self, name: str, default: float = 0.0) -> float:
        return self.values.get(name, default)

    def require(self, *names: str) -> tuple[float, ...]:
        """Fetch features, refusing to substitute zero for a missing one.

        Silently defaulting a missing feature to 0.0 is how a broken feature
        pipeline turns into "no alerts" instead of an error.
        """
        missing = [n for n in names if n not in self.values]
        if missing:
            raise KeyError(f"feature vector {self.entity_id} missing {missing}")
        return tuple(self.values[n] for n in names)


class DetectorMetadata(Frozen):
    """Identity and lineage of a detector instance."""

    name: ShortText
    detector_version: SemVer
    technique: Technique
    threat_class: ThreatClass
    state: DetectorState = DetectorState.READY
    state_reason: ShortText | None = None
    model_version: ShortText | None = None
    feature_schema_version: SemVer = FEATURE_SCHEMA_VERSION


class DetectorInput(Strict):
    """What a detector is allowed to look at: features plus read-only context."""

    features: FeatureVector
    timestamp: datetime
    context: dict[str, float | str | bool | None] = Field(default_factory=dict)

    _validate_ts = field_validator("timestamp", mode="before")(_to_utc)


class DetectorResult(Frozen):
    """Immutable verdict from one detector for one feature vector.

    ``score`` is the detector's native scale (documented per detector).
    ``confidence`` is normalised to [0, 1] and ``confidence_basis`` records how it
    was produced, so it can be recomputed and audited later.
    """

    detector_name: ShortText
    detector_version: SemVer
    threat_class: ThreatClass
    technique: Technique
    score: float
    confidence: UnitFloat
    confidence_basis: ConfidenceBasis
    severity_hint: Severity
    timestamp: datetime
    entity_kind: EntityKind
    entity_id: ShortText
    window_seconds: NonNegFloat
    src_ip: str | None = None
    dst_ip: str | None = None
    supporting_features: dict[str, float] = Field(default_factory=dict)
    reason_codes: list[ShortText] = Field(default_factory=list, max_length=32)
    model_version: ShortText | None = None
    feature_schema_version: SemVer = FEATURE_SCHEMA_VERSION
    shadow: bool = False
    flow_ids: list[ShortText] = Field(default_factory=list, max_length=64)
    pcap_references: list[ShortText] = Field(default_factory=list, max_length=8)

    _validate_ts = field_validator("timestamp", mode="before")(_to_utc)

    @property
    def fired(self) -> bool:
        return self.threat_class is not ThreatClass.BENIGN


class Evidence(Frozen):
    """Human- and machine-readable justification attached to every alert."""

    summary: Note
    reason_codes: list[ShortText] = Field(default_factory=list, max_length=64)
    observations: dict[str, float] = Field(default_factory=dict)
    baseline_comparisons: dict[str, float] = Field(default_factory=dict)
    detector_contributions: dict[str, float] = Field(default_factory=dict)
    feature_importances: dict[str, float] = Field(default_factory=dict)
    flow_ids: list[ShortText] = Field(default_factory=list, max_length=128)
    pcap_references: list[ShortText] = Field(default_factory=list, max_length=16)


class Lineage(Frozen):
    """Exactly which code and artefacts produced a verdict."""

    detector_versions: dict[str, str] = Field(default_factory=dict)
    model_versions: dict[str, str] = Field(default_factory=dict)
    feature_schema_version: SemVer = FEATURE_SCHEMA_VERSION
    event_schema_version: SemVer = EVENT_SCHEMA_VERSION
    pipeline_run_id: ShortText | None = None


class Alert(Frozen):
    """Terminal output of the detection pipeline. Contains no payload content."""

    schema_version: SemVer = ALERT_SCHEMA_VERSION
    alert_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime
    first_seen: datetime
    last_seen: datetime

    threat_class: ThreatClass
    confidence: UnitFloat
    confidence_basis: ConfidenceBasis
    severity: Severity
    status: AlertStatus = AlertStatus.NEW

    src_ip: str | None = None
    dst_ip: str | None = None
    entity_kind: EntityKind
    entity_id: ShortText

    detector_name: ShortText
    detector_version: SemVer
    technique: Technique
    model_version: ShortText | None = None
    feature_schema_version: SemVer = FEATURE_SCHEMA_VERSION

    correlation_id: ShortText | None = None
    incident_id: ShortText | None = None
    event_count: NonNegInt = 0
    dedup_count: NonNegInt = 1

    evidence: Evidence
    lineage: Lineage = Field(default_factory=Lineage)
    contributing_detectors: list[ShortText] = Field(default_factory=list, max_length=16)

    _validate_ts = field_validator("timestamp", "first_seen", "last_seen", mode="before")(_to_utc)

    @field_validator("schema_version")
    @classmethod
    def _known_version(cls, v: str) -> str:
        if v != ALERT_SCHEMA_VERSION:
            raise ValueError(f"unsupported alert schema_version {v!r}")
        return v


class Incident(Frozen):
    """Correlated group of alerts sharing an entity and a temporal window."""

    incident_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    first_seen: datetime
    last_seen: datetime
    entity_kind: EntityKind
    entity_id: ShortText
    primary_threat_class: ThreatClass
    threat_classes: list[ThreatClass] = Field(default_factory=list, max_length=16)
    severity: Severity
    confidence: UnitFloat
    alert_ids: list[ShortText] = Field(default_factory=list, max_length=512)
    alert_count: NonNegInt = 0
    summary: Note = ""
    status: AlertStatus = AlertStatus.NEW

    _validate_ts = field_validator(
        "created_at", "updated_at", "first_seen", "last_seen", mode="before"
    )(_to_utc)


class AnalystFeedback(Strict):
    """Operator judgement on an alert. Becomes a *training candidate*, nothing more."""

    feedback_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    alert_id: ShortText
    label: FeedbackLabel
    corrected_threat_class: ThreatClass | None = None
    analyst_id: ShortText = "unassigned"
    analyst_confidence: UnitFloat | None = None
    notes: Note = ""
    timestamp: datetime = Field(default_factory=utcnow)

    _validate_ts = field_validator("timestamp", mode="before")(_to_utc)

    @model_validator(mode="after")
    def _require_class_for_fn(self) -> "AnalystFeedback":
        if self.label is FeedbackLabel.FALSE_NEGATIVE and self.corrected_threat_class is None:
            raise ValueError("FALSE_NEGATIVE feedback must state corrected_threat_class")
        return self


class DriftEvent(Frozen):
    """A drift *signal*. Never triggers retraining or deployment by itself."""

    drift_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=utcnow)
    detector: ShortText
    model_version: ShortText | None = None
    feature: ShortText | None = None
    drift_type: DriftType
    metric: ShortText
    score: float
    threshold: float
    window: ShortText
    reference_size: NonNegInt = 0
    current_size: NonNegInt = 0
    recommendation: Note = ""

    _validate_ts = field_validator("timestamp", mode="before")(_to_utc)

    @property
    def breached(self) -> bool:
        return self.score >= self.threshold


class DatasetMetadata(Frozen):
    """Provenance of a training dataset. Written once, never mutated."""

    dataset_id: ShortText
    created_at: datetime = Field(default_factory=utcnow)
    feature_schema_version: SemVer = FEATURE_SCHEMA_VERSION
    detector: ShortText
    source_summary: dict[str, int] = Field(default_factory=dict)
    class_distribution: dict[str, int] = Field(default_factory=dict)
    split_strategy: ShortText
    split_sizes: dict[str, int] = Field(default_factory=dict)
    feature_names: list[str] = Field(default_factory=list)
    label_provenance: dict[str, int] = Field(default_factory=dict)
    content_hash: Sha256
    row_count: NonNegInt = 0
    seed: int = 0

    _validate_ts = field_validator("created_at", mode="before")(_to_utc)


class ModelMetadata(Frozen):
    """Registry entry for one model artefact."""

    detector: ShortText
    model_id: ShortText
    model_version: ShortText
    artifact_path: ShortText
    artifact_hash: Sha256
    estimator_class: ShortText
    feature_schema_version: SemVer
    feature_names: list[str] = Field(default_factory=list)
    dataset_id: ShortText | None = None
    training_time: datetime = Field(default_factory=utcnow)
    training_duration_seconds: NonNegFloat = 0.0
    metrics: dict[str, float] = Field(default_factory=dict)
    status: ModelStatus = ModelStatus.CANDIDATE
    seed: int = 0
    notes: Note = ""

    _validate_ts = field_validator("training_time", mode="before")(_to_utc)


class PromotionRecord(Frozen):
    """Append-only audit row for every registry status change."""

    record_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=utcnow)
    detector: ShortText
    model_version: ShortText
    from_status: ModelStatus | None = None
    to_status: ModelStatus
    actor: ShortText = "cli"
    reason: Note = ""
    gate_results: dict[str, bool] = Field(default_factory=dict)
    previous_champion: ShortText | None = None

    _validate_ts = field_validator("timestamp", mode="before")(_to_utc)


class BenchmarkResult(Frozen):
    """A *measured* performance run. Never populated with estimates."""

    benchmark_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=utcnow)
    name: ShortText
    events: NonNegInt
    duration_seconds: NonNegFloat
    events_per_second: NonNegFloat
    latency_p50_ms: NonNegFloat | None = None
    latency_p95_ms: NonNegFloat | None = None
    latency_p99_ms: NonNegFloat | None = None
    latency_max_ms: NonNegFloat | None = None
    stage_seconds: dict[str, float] = Field(default_factory=dict)
    alerts_generated: NonNegInt = 0
    hardware: Note = ""
    configuration: dict[str, str] = Field(default_factory=dict)
    model_versions: dict[str, str] = Field(default_factory=dict)
    dataset: ShortText | None = None

    _validate_ts = field_validator("timestamp", mode="before")(_to_utc)


class ThreatIntelIndicator(Frozen):
    """Normalised external indicator. Data only -- never executed, never auto-applied."""

    indicator_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    kind: Literal["domain", "ip", "ja4", "ja4s", "sha256"]
    value: ShortText
    source: ShortText
    first_seen: datetime | None = None
    confidence: UnitFloat | None = None
    tags: list[ShortText] = Field(default_factory=list, max_length=32)
    ingested_at: datetime = Field(default_factory=utcnow)
    reviewed: bool = False

    _validate_ts = field_validator("first_seen", "ingested_at", mode="before")(_to_utc)

    @model_validator(mode="after")
    def _validate_value(self) -> "ThreatIntelIndicator":
        if self.kind == "domain":
            object.__setattr__(self, "value", normalise_domain(self.value))
        elif self.kind == "sha256" and not (
            len(self.value) == 64 and all(c in "0123456789abcdef" for c in self.value.lower())
        ):
            raise ValueError("sha256 indicator is not a 64-char hex digest")
        return self
