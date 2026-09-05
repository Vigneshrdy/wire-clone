"""DGA (algorithmically-generated domain) detection from DNS metadata.

The only supervised detector in the mesh, because the signal genuinely is a
learned lexical one: no small set of thresholds separates ``kq3x9zvbmwlp.com``
from ``spotifycdn.com`` without a large false-positive rate.

Inference uses the CHAMPION model from the registry. With no champion registered
the detector reports ``UNAVAILABLE`` and returns nothing -- it never falls back to
a hand-made score, because a fabricated probability presented as a model output is
worse than an honest gap.

Features come from :func:`sih_ntd.features.stats.dns_lexical_features`, the same
function the trainer uses, and the model's recorded ``feature_names`` fixes the
column order. A model trained under a different feature schema version is refused
by the registry rather than silently mis-fed.

Architecture note: swapping in a character-level neural model means registering an
artefact with a ``predict_proba`` and the same feature contract. Nothing in this
file assumes a linear model.
"""

from __future__ import annotations

from typing import Any

from ..config import Settings
from ..errors import ArtifactIntegrityError, SchemaVersionMismatch
from ..ml.registry import ModelRegistry
from ..schemas import (
    ConfidenceBasis,
    DetectorInput,
    DetectorResult,
    DetectorState,
    EntityKind,
    ModelMetadata,
    Severity,
    Technique,
    ThreatClass,
)
from .base import Detector

#: Domains this short are almost never DGA and dominate the false positives.
MIN_LABELS = 2


class DgaDetector(Detector):
    name = "dga"
    version = "1.0.0"
    threat_class = ThreatClass.DGA
    technique = Technique.SUPERVISED
    confidence_basis = ConfidenceBasis.CALIBRATED_PROBABILITY
    entity_kinds = (EntityKind.HOST,)
    per_event = True

    def __init__(self, settings: Settings | None = None, registry: ModelRegistry | None = None) -> None:
        super().__init__(settings)
        self.registry = registry or ModelRegistry(settings=self.settings)
        self._champion: tuple[ModelMetadata, Any] | None = None
        self._challenger: tuple[ModelMetadata, Any] | None = None
        self._unavailable_reason: str | None = None
        self._load()

    # --- model lifecycle -------------------------------------------------
    def _load(self) -> None:
        """Load champion (and challenger, for shadow scoring) once at startup.

        Deliberately not hot-reloading: a model swap under a running pipeline
        would make alerts non-reproducible mid-stream. Promotion is followed by a
        worker restart -- see docs/CONTINUOUS_LEARNING.md.
        """
        try:
            self._champion = self.registry.load_champion(self.name)
            if self._champion is None:
                self._unavailable_reason = (
                    "no CHAMPION model registered for 'dga'; train one with "
                    "`sih-ntd train-dga`"
                )
                return
            challenger_meta = self.registry.challenger(self.name)
            if challenger_meta is not None:
                self._challenger = (challenger_meta, self.registry.load(challenger_meta))
            self._unavailable_reason = None
        except (ArtifactIntegrityError, SchemaVersionMismatch) as exc:
            self._champion = None
            self._unavailable_reason = str(exc)

    def state(self) -> DetectorState:
        return DetectorState.READY if self._champion else DetectorState.UNAVAILABLE

    def state_reason(self) -> str | None:
        return self._unavailable_reason

    @property
    def model_version(self) -> str | None:
        return self._champion[0].model_version if self._champion else None

    def accepts(self, features) -> bool:  # type: ignore[override]
        return super().accepts(features) and features.get("dns_event") == 1.0

    # --- inference -------------------------------------------------------
    def _probability(self, model: tuple[ModelMetadata, Any], features) -> float:
        metadata, estimator = model
        row = [[features.get(name) for name in metadata.feature_names]]
        # predict_proba column 1 is the positive (DGA) class; the trainer
        # guarantees classes_ == [0, 1].
        return float(estimator.predict_proba(row)[0][1])

    def evaluate(self, payload: DetectorInput) -> DetectorResult | None:
        if self._champion is None:
            return None
        f = payload.features
        t = self.thresholds

        domain = f.labels.get("dns_query", "")
        if f.get("dns_label_count") < MIN_LABELS:
            return None
        if f.get("dns_payload_length") < t.dga_min_domain_length:
            return None

        probability = self._probability(self._champion, f)
        if probability < t.dga_probability:
            return None

        reason_codes = ["DGA_MODEL_POSITIVE"]
        if f.get("dns_is_nxdomain") == 1.0:
            # NXDOMAIN is the classic DGA tell: most generated names are not
            # registered, so the malware walks through failures.
            reason_codes.append("NXDOMAIN_RESPONSE")
        if f.get("dns_nxdomain_ratio_60s") >= 0.5 and f.get("dns_query_count_60s") >= 10:
            reason_codes.append("HOST_NXDOMAIN_BURST")
        if f.get("dns_char_entropy") >= 3.5:
            reason_codes.append("HIGH_NAME_ENTROPY")

        supporting = {
            "dga_probability": probability,
            "probability_threshold": t.dga_probability,
            **{name: f.get(name) for name in self._champion[0].feature_names},
            "dns_nxdomain_ratio_60s": f.get("dns_nxdomain_ratio_60s"),
            "dns_query_count_60s": f.get("dns_query_count_60s"),
        }
        result = self.build_result(
            f,
            score=probability,
            confidence=probability,  # already a calibrated probability
            severity=self._severity(probability, reason_codes),
            reason_codes=reason_codes,
            supporting=supporting,
        )
        # Evidence needs the domain, which is a label rather than a feature.
        return result.model_copy(
            update={"supporting_features": {**result.supporting_features, "domain_length": float(len(domain))}}
        )

    def shadow_evaluate(self, payload: DetectorInput) -> DetectorResult | None:
        """Score with the CHALLENGER for offline comparison.

        The returned result carries ``shadow=True``; the pipeline records it and
        never turns it into an alert.
        """
        if self._challenger is None or not self.accepts(payload.features):
            return None
        f = payload.features
        if f.get("dns_payload_length") < self.thresholds.dga_min_domain_length:
            return None
        probability = self._probability(self._challenger, f)
        base = self.build_result(
            f,
            score=probability,
            confidence=probability,
            severity=Severity.INFO,
            reason_codes=["SHADOW_INFERENCE"],
            supporting={"dga_probability": probability},
        )
        return base.model_copy(
            update={"shadow": True, "model_version": self._challenger[0].model_version}
        )

    def _severity(self, probability: float, reason_codes: list[str]) -> Severity:
        """A resolving DGA domain matters more than one that NXDOMAINs.

        A successful resolution means the algorithm found a live rendezvous point,
        i.e. the host may now have a working C2 channel.
        """
        resolved = "NXDOMAIN_RESPONSE" not in reason_codes
        if probability >= 0.95 and resolved:
            return Severity.HIGH
        if probability >= 0.95 or resolved:
            return Severity.MEDIUM
        return Severity.LOW
