"""Model + feature registry backed by the filesystem.

Layout::

    ml_artifacts/<detector>/models/<model_version>.json     ModelMetadata
    ml_artifacts/<detector>/models/<model_version>.joblib   the artefact
    ml_artifacts/<detector>/promotions.jsonl                append-only audit log

A directory tree rather than a service: it is inspectable with ``cat``, it diffs
in git (metadata is committed, binaries are not), and it needs no extra
container. The whole registry is one file, so replacing it with a real MLflow-like
backend later touches nothing else.

Artifact trust model
--------------------
``joblib.load`` executes pickle opcodes, so it is only ever called on a file whose
SHA-256 matches the hash recorded when *this system* produced it, and the loaded
object's class name is checked against the recorded ``estimator_class``. An
artefact from anywhere else is refused (:class:`ArtifactIntegrityError`) rather
than loaded and hoped about. See docs/SECURITY_MODEL.md.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib

from ..config import Settings, get_settings
from ..errors import ArtifactIntegrityError, SchemaVersionMismatch
from ..schemas import (
    FEATURE_SCHEMA_VERSION,
    ModelMetadata,
    ModelStatus,
    PromotionRecord,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ModelRegistry:
    """Filesystem model registry with explicit, auditable promotion."""

    def __init__(self, root: Path | None = None, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.root = Path(root or self.settings.registry.root)
        self.root.mkdir(parents=True, exist_ok=True)

    # --- paths -----------------------------------------------------------
    #: Subdirectory of the registry root that holds datasets, not models.
    DATASETS_DIR = "datasets"

    def detector_dir(self, detector: str, *, create: bool = False) -> Path:
        """Path to a detector's model directory.

        ``create`` is opt-in so that merely *reading* the registry for a detector
        with no models does not litter the tree with empty directories -- which made
        an unavailable detector show up in ``GET /api/v1/models``.
        """
        path = self.root / detector / "models"
        if create:
            path.mkdir(parents=True, exist_ok=True)
        return path

    def metadata_path(self, detector: str, model_version: str, *, create: bool = False) -> Path:
        return self.detector_dir(detector, create=create) / f"{model_version}.json"

    def artifact_path(self, detector: str, model_version: str, *, create: bool = False) -> Path:
        return self.detector_dir(detector, create=create) / f"{model_version}.joblib"

    def promotions_path(self, detector: str) -> Path:
        return self.root / detector / "promotions.jsonl"

    # --- registration ----------------------------------------------------
    def register(
        self,
        *,
        detector: str,
        model_version: str,
        estimator: Any,
        feature_names: list[str],
        metrics: dict[str, float],
        dataset_id: str | None,
        training_duration_seconds: float = 0.0,
        seed: int = 0,
        notes: str = "",
        feature_schema_version: str = FEATURE_SCHEMA_VERSION,
    ) -> ModelMetadata:
        """Persist an artefact plus its metadata as a CANDIDATE."""
        artifact = self.artifact_path(detector, model_version, create=True)
        if artifact.exists():
            raise FileExistsError(f"{detector}/{model_version} already registered")
        joblib.dump(estimator, artifact)
        metadata = ModelMetadata(
            detector=detector,
            model_id=f"{detector}-{model_version}",
            model_version=model_version,
            artifact_path=str(artifact.relative_to(self.root)),
            artifact_hash=sha256_file(artifact),
            estimator_class=type(estimator).__name__,
            feature_schema_version=feature_schema_version,
            feature_names=list(feature_names),
            dataset_id=dataset_id,
            training_duration_seconds=training_duration_seconds,
            metrics=dict(metrics),
            status=ModelStatus.CANDIDATE,
            seed=seed,
            notes=notes,
        )
        self._write_metadata(metadata)
        self._append_promotion(
            PromotionRecord(
                detector=detector,
                model_version=model_version,
                from_status=None,
                to_status=ModelStatus.CANDIDATE,
                actor="trainer",
                reason="initial registration",
            )
        )
        return metadata

    def _write_metadata(self, metadata: ModelMetadata) -> None:
        path = self.metadata_path(metadata.detector, metadata.model_version, create=True)
        path.write_text(metadata.model_dump_json(indent=2))

    def _append_promotion(self, record: PromotionRecord) -> None:
        path = self.promotions_path(record.detector)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as handle:
            handle.write(record.model_dump_json() + "\n")

    # --- lookup ----------------------------------------------------------
    def detectors(self) -> list[str]:
        """Detector names that actually have a models directory."""
        return sorted(
            p.name
            for p in self.root.iterdir()
            if p.is_dir() and p.name != self.DATASETS_DIR and (p / "models").is_dir()
        )

    def list_models(self, detector: str) -> list[ModelMetadata]:
        models = [
            ModelMetadata.model_validate_json(path.read_text())
            for path in sorted(self.detector_dir(detector).glob("*.json"))
        ]
        return sorted(models, key=lambda m: m.training_time, reverse=True)

    def get(self, detector: str, model_version: str) -> ModelMetadata | None:
        path = self.metadata_path(detector, model_version)
        if not path.exists():
            return None
        return ModelMetadata.model_validate_json(path.read_text())

    def by_status(self, detector: str, status: ModelStatus) -> ModelMetadata | None:
        for model in self.list_models(detector):
            if model.status is status:
                return model
        return None

    def champion(self, detector: str) -> ModelMetadata | None:
        return self.by_status(detector, ModelStatus.CHAMPION)

    def challenger(self, detector: str) -> ModelMetadata | None:
        return self.by_status(detector, ModelStatus.CHALLENGER)

    def promotion_history(self, detector: str) -> list[PromotionRecord]:
        path = self.promotions_path(detector)
        if not path.exists():
            return []
        return [
            PromotionRecord.model_validate_json(line)
            for line in path.read_text().splitlines()
            if line.strip()
        ]

    # --- loading ---------------------------------------------------------
    def load(self, metadata: ModelMetadata) -> Any:
        """Load an artefact after verifying integrity and feature compatibility."""
        if metadata.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise SchemaVersionMismatch(
                f"{metadata.model_id} was trained against feature schema "
                f"{metadata.feature_schema_version}; this build runs "
                f"{FEATURE_SCHEMA_VERSION}. Retrain before use."
            )
        artifact = self.root / metadata.artifact_path
        if not artifact.exists():
            raise ArtifactIntegrityError(f"artifact missing: {artifact}")
        actual = sha256_file(artifact)
        if actual != metadata.artifact_hash:
            raise ArtifactIntegrityError(
                f"artifact hash mismatch for {metadata.model_id}: "
                f"recorded {metadata.artifact_hash[:12]}, found {actual[:12]}"
            )
        estimator = joblib.load(artifact)
        if type(estimator).__name__ != metadata.estimator_class:
            raise ArtifactIntegrityError(
                f"{metadata.model_id} contains {type(estimator).__name__}, "
                f"expected {metadata.estimator_class}"
            )
        return estimator

    def load_champion(self, detector: str) -> tuple[ModelMetadata, Any] | None:
        metadata = self.champion(detector)
        if metadata is None:
            return None
        return metadata, self.load(metadata)

    # --- status transitions ----------------------------------------------
    def set_status(
        self,
        detector: str,
        model_version: str,
        status: ModelStatus,
        *,
        actor: str = "cli",
        reason: str = "",
        gate_results: dict[str, bool] | None = None,
    ) -> ModelMetadata:
        """Change a model's status and append an audit record.

        Promoting to CHAMPION retires the incumbent, and the record names it so
        :meth:`rollback` can restore it without guessing.
        """
        metadata = self.get(detector, model_version)
        if metadata is None:
            raise FileNotFoundError(f"{detector}/{model_version} is not registered")
        previous_champion: str | None = None
        if status is ModelStatus.CHAMPION:
            incumbent = self.champion(detector)
            if incumbent is not None and incumbent.model_version != model_version:
                previous_champion = incumbent.model_version
                self._write_metadata(
                    incumbent.model_copy(update={"status": ModelStatus.RETIRED})
                )
                self._append_promotion(
                    PromotionRecord(
                        detector=detector,
                        model_version=incumbent.model_version,
                        from_status=ModelStatus.CHAMPION,
                        to_status=ModelStatus.RETIRED,
                        actor=actor,
                        reason=f"superseded by {model_version}",
                    )
                )
        updated = metadata.model_copy(update={"status": status})
        self._write_metadata(updated)
        self._append_promotion(
            PromotionRecord(
                detector=detector,
                model_version=model_version,
                from_status=metadata.status,
                to_status=status,
                actor=actor,
                reason=reason,
                gate_results=gate_results or {},
                previous_champion=previous_champion,
            )
        )
        return updated

    def rollback(self, detector: str, *, actor: str = "cli", reason: str = "rollback") -> ModelMetadata:
        """Restore the champion that the current one replaced."""
        current = self.champion(detector)
        if current is None:
            raise FileNotFoundError(f"{detector} has no champion to roll back")
        target: str | None = None
        for record in reversed(self.promotion_history(detector)):
            if (
                record.model_version == current.model_version
                and record.to_status is ModelStatus.CHAMPION
                and record.previous_champion
            ):
                target = record.previous_champion
                break
        if target is None:
            raise FileNotFoundError(
                f"no previous champion recorded for {detector}; nothing to roll back to"
            )
        self.set_status(
            detector, current.model_version, ModelStatus.RETIRED, actor=actor, reason=reason
        )
        return self.set_status(
            detector, target, ModelStatus.CHAMPION, actor=actor, reason=f"{reason} from {current.model_version}"
        )

    # --- helpers ---------------------------------------------------------
    @staticmethod
    def next_version(existing: list[ModelMetadata]) -> str:
        """``YYYYMMDD-N`` -- date plus a per-day counter. Sorts naturally."""
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        same_day = [m for m in existing if m.model_version.startswith(today)]
        return f"{today}-{len(same_day) + 1}"

    def summary(self) -> dict[str, dict[str, Any]]:
        """Registry state for ``GET /api/v1/models``."""
        out: dict[str, dict[str, Any]] = {}
        for detector in self.detectors():
            champion = self.champion(detector)
            challenger = self.challenger(detector)
            out[detector] = {
                "champion": champion.model_dump(mode="json") if champion else None,
                "challenger": challenger.model_dump(mode="json") if challenger else None,
                "model_count": len(self.list_models(detector)),
            }
        return out
