"""The detector contract.

Every detector -- rule, statistical or supervised -- implements this interface so
the pipeline, the API and the fusion layer never special-case one of them.

Three rules the contract enforces:

1. A detector reads a :class:`FeatureVector` and nothing else. It cannot query the
   network, open a socket, or reach back toward a monitored host.
2. A detector that cannot run says so (``DetectorState.UNAVAILABLE``) instead of
   returning a made-up score. See :class:`~sih_ntd.errors.DetectorUnavailable`.
3. Output is immutable. Fusion builds new records; it never edits results.
"""

from __future__ import annotations

import abc
import time

from ..config import Settings, get_settings
from ..errors import DetectorUnavailable
from ..metrics import DETECTOR_ERRORS, DETECTOR_RESULTS, DETECTOR_STATE, INFERENCE_LATENCY
from ..schemas import (
    ConfidenceBasis,
    DetectorInput,
    DetectorMetadata,
    DetectorResult,
    DetectorState,
    EntityKind,
    FeatureVector,
    Severity,
    Technique,
    ThreatClass,
)


class Detector(abc.ABC):
    """Base class. Subclasses implement :meth:`accepts` and :meth:`evaluate`."""

    name: str = "unnamed"
    version: str = "0.1.0"
    threat_class: ThreatClass = ThreatClass.BENIGN
    technique: Technique = Technique.RULE
    confidence_basis: ConfidenceBasis = ConfidenceBasis.RULE_EVIDENCE
    #: Entity perspectives this detector is meaningful for.
    entity_kinds: tuple[EntityKind, ...] = ()
    #: True for detectors that consume per-event protocol vectors
    #: (``window_seconds == 0.0``) rather than windowed ones.
    per_event: bool = False

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.thresholds = self.settings.thresholds

    # --- lifecycle -------------------------------------------------------
    def state(self) -> DetectorState:
        """Runtime availability. Overridden by model-backed detectors."""
        return DetectorState.READY

    def state_reason(self) -> str | None:
        return None

    @property
    def model_version(self) -> str | None:
        return None

    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name=self.name,
            detector_version=self.version,
            technique=self.technique,
            threat_class=self.threat_class,
            state=self.state(),
            state_reason=self.state_reason(),
            model_version=self.model_version,
        )

    # --- evaluation ------------------------------------------------------
    def accepts(self, features: FeatureVector) -> bool:
        """Cheap pre-filter so the hot path skips irrelevant vectors."""
        if self.entity_kinds and features.entity_kind not in self.entity_kinds:
            return False
        if self.per_event:
            return features.window_seconds == 0.0
        return features.window_seconds > 0.0

    @abc.abstractmethod
    def evaluate(self, payload: DetectorInput) -> DetectorResult | None:
        """Return a result, or None when there is nothing worth reporting.

        Returning None is the normal case: a benign window produces no record, so
        the store is not filled with millions of "BENIGN" rows.
        """

    # --- helpers ---------------------------------------------------------
    def build_result(
        self,
        features: FeatureVector,
        *,
        score: float,
        confidence: float,
        severity: Severity,
        reason_codes: list[str],
        supporting: dict[str, float],
        threat_class: ThreatClass | None = None,
    ) -> DetectorResult:
        return DetectorResult(
            detector_name=self.name,
            detector_version=self.version,
            threat_class=threat_class or self.threat_class,
            technique=self.technique,
            score=float(score),
            confidence=max(0.0, min(1.0, float(confidence))),
            confidence_basis=self.confidence_basis,
            severity_hint=severity,
            timestamp=features.timestamp,
            entity_kind=features.entity_kind,
            entity_id=features.entity_id,
            window_seconds=features.window_seconds,
            src_ip=features.labels.get("src_ip"),
            dst_ip=features.labels.get("dst_ip"),
            supporting_features={k: float(v) for k, v in supporting.items()},
            reason_codes=reason_codes[:32],
            model_version=self.model_version,
            feature_schema_version=features.schema_version,
            flow_ids=list(features.flow_ids),
            pcap_references=list(features.pcap_references),
        )

    @staticmethod
    def escalate(severity: Severity, steps: int = 1) -> Severity:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order[min(len(order) - 1, order.index(severity) + steps)]


def safe_evaluate(detector: Detector, payload: DetectorInput) -> DetectorResult | None:
    """Run one detector without letting it take the pipeline down.

    An exception inside one detector must not stop the other six from seeing the
    same window; the failure is counted and logged, and the window continues.
    """
    started = time.perf_counter()
    try:
        result = detector.evaluate(payload)
    except DetectorUnavailable:
        DETECTOR_STATE.set(0, detector=detector.name)
        return None
    except Exception:  # noqa: BLE001 -- deliberate isolation boundary
        DETECTOR_ERRORS.inc(detector=detector.name)
        return None
    finally:
        INFERENCE_LATENCY.observe(time.perf_counter() - started, detector=detector.name)
    DETECTOR_RESULTS.inc(detector=detector.name, fired="1" if result is not None else "0")
    return result


class DetectorRegistry:
    """The detection mesh: an ordered collection of detectors."""

    def __init__(self, detectors: list[Detector]) -> None:
        self._detectors = detectors
        for detector in detectors:
            DETECTOR_STATE.set(
                1 if detector.state() is DetectorState.READY else 0, detector=detector.name
            )

    def __iter__(self):
        return iter(self._detectors)

    def __len__(self) -> int:
        return len(self._detectors)

    def get(self, name: str) -> Detector | None:
        return next((d for d in self._detectors if d.name == name), None)

    def ready(self) -> list[Detector]:
        return [d for d in self._detectors if d.state() is DetectorState.READY]

    def metadata(self) -> list[DetectorMetadata]:
        return [d.metadata() for d in self._detectors]

    def evaluate(self, features: FeatureVector) -> list[DetectorResult]:
        """Fan one feature vector out to every detector that accepts it."""
        payload = DetectorInput(features=features, timestamp=features.timestamp)
        results: list[DetectorResult] = []
        for detector in self._detectors:
            if detector.state() is not DetectorState.READY or not detector.accepts(features):
                continue
            result = safe_evaluate(detector, payload)
            if result is not None:
                results.append(result)
        return results


def build_default_registry(settings: Settings | None = None) -> DetectorRegistry:
    """Construct the full mesh. Imported lazily to avoid an import cycle."""
    from .c2 import C2BeaconDetector
    from .ddos import DDoSDetector
    from .dga import DgaDetector
    from .dns_tunnel import DnsTunnelDetector
    from .exfiltration import ExfiltrationDetector
    from .recon import ReconDetector
    from .tls_malware import TlsMalwareDetector

    settings = settings or get_settings()
    return DetectorRegistry(
        [
            DDoSDetector(settings),
            ReconDetector(settings),
            C2BeaconDetector(settings),
            DgaDetector(settings),
            DnsTunnelDetector(settings),
            TlsMalwareDetector(settings),
            ExfiltrationDetector(settings),
        ]
    )
