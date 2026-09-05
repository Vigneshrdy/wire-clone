"""Registry and governance: promotion is explicit, reversible and audited."""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

from sih_ntd.errors import ArtifactIntegrityError, SchemaVersionMismatch
from sih_ntd.ml.governance import PromotionGate
from sih_ntd.ml.registry import ModelRegistry
from sih_ntd.schemas import ModelStatus


@pytest.fixture
def registry(settings) -> ModelRegistry:
    return ModelRegistry(settings=settings)


@pytest.fixture
def estimator():
    return LogisticRegression().fit(np.array([[0.0], [1.0], [2.0], [3.0]]), [0, 0, 1, 1])


def register(registry, estimator, version: str, **metrics_overrides):
    metrics = {
        "precision": 0.96, "recall": 0.9, "f1": 0.93, "false_positive_rate": 0.005,
        "inference_latency_ms": 0.4, "independent_generator_recall": 0.8,
        "independent_benign_fpr": 0.0,
    }
    metrics.update(metrics_overrides)
    return registry.register(
        detector="dga", model_version=version, estimator=estimator, feature_names=["x"],
        metrics=metrics, dataset_id="ds-1",
    )


def test_registration_starts_as_candidate_not_champion(registry, estimator):
    metadata = register(registry, estimator, "v1")
    assert metadata.status is ModelStatus.CANDIDATE
    assert registry.champion("dga") is None, "training must never promote"


def test_promotion_retires_the_incumbent_and_records_it(registry, estimator):
    register(registry, estimator, "v1")
    register(registry, estimator, "v2")
    registry.set_status("dga", "v1", ModelStatus.CHAMPION, reason="first")
    registry.set_status("dga", "v2", ModelStatus.CHAMPION, reason="better")
    assert registry.champion("dga").model_version == "v2"
    assert registry.get("dga", "v1").status is ModelStatus.RETIRED
    record = [
        r for r in registry.promotion_history("dga")
        if r.model_version == "v2" and r.to_status is ModelStatus.CHAMPION
    ][0]
    assert record.previous_champion == "v1"


def test_rollback_restores_the_previous_champion(registry, estimator):
    register(registry, estimator, "v1")
    register(registry, estimator, "v2")
    registry.set_status("dga", "v1", ModelStatus.CHAMPION)
    registry.set_status("dga", "v2", ModelStatus.CHAMPION)
    assert registry.rollback("dga").model_version == "v1"
    assert registry.champion("dga").model_version == "v1"


def test_rollback_without_history_is_refused(registry, estimator):
    register(registry, estimator, "v1")
    registry.set_status("dga", "v1", ModelStatus.CHAMPION)
    with pytest.raises(FileNotFoundError, match="no previous champion"):
        registry.rollback("dga")


def test_tampered_artifact_is_refused(registry, estimator):
    metadata = register(registry, estimator, "v1")
    artifact = registry.root / metadata.artifact_path
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    with pytest.raises(ArtifactIntegrityError, match="hash mismatch"):
        registry.load(metadata)


def test_missing_artifact_is_refused(registry, estimator):
    metadata = register(registry, estimator, "v1")
    (registry.root / metadata.artifact_path).unlink()
    with pytest.raises(ArtifactIntegrityError, match="missing"):
        registry.load(metadata)


def test_model_from_a_different_feature_schema_is_refused(registry, estimator):
    metadata = register(registry, estimator, "v1")
    stale = metadata.model_copy(update={"feature_schema_version": "0.9.0"})
    with pytest.raises(SchemaVersionMismatch, match="Retrain"):
        registry.load(stale)


def test_registry_lists_only_detectors_with_models(registry, estimator):
    register(registry, estimator, "v1")
    assert registry.detectors() == ["dga"]
    assert registry.summary()["dga"]["model_count"] == 1


def test_gate_passes_a_sound_candidate(registry, estimator):
    assert PromotionGate().evaluate(register(registry, estimator, "v1")).passed


def test_gate_blocks_weak_metrics(registry, estimator):
    report = PromotionGate().evaluate(
        register(registry, estimator, "v1", precision=0.5, recall=0.3,
                 false_positive_rate=0.4, inference_latency_ms=50.0)
    )
    assert not report.passed
    assert {"precision", "recall", "false_positive_rate", "inference_latency"} <= set(report.failures)


def test_gate_blocks_a_model_that_memorised_its_training_generators(registry, estimator):
    """The failure this project actually hit: perfect in-distribution, zero transfer."""
    report = PromotionGate().evaluate(
        register(registry, estimator, "v1", independent_generator_recall=0.0)
    )
    assert "generalises_to_independent_generator" in report.failures


def test_gate_is_suspicious_of_perfect_scores(registry, estimator):
    report = PromotionGate().evaluate(
        register(registry, estimator, "v1", precision=1.0, recall=1.0)
    )
    assert "not_implausibly_perfect" in report.failures


def test_acknowledged_gates_do_not_block_but_are_recorded(registry, estimator):
    report = PromotionGate().evaluate(
        register(registry, estimator, "v1", precision=1.0, recall=1.0),
        acknowledge={"not_implausibly_perfect"},
    )
    assert report.passed
    assert "not_implausibly_perfect" in report.acknowledged
    assert report.failures == {}


def test_gate_requires_dataset_provenance(registry, estimator):
    metadata = register(registry, estimator, "v1").model_copy(update={"dataset_id": None})
    assert "dataset_recorded" in PromotionGate().evaluate(metadata).failures


def test_gate_requires_improvement_over_champion(registry, estimator):
    champion = register(registry, estimator, "v1", f1=0.95)
    challenger = register(registry, estimator, "v2", f1=0.80)
    report = PromotionGate().evaluate(challenger, champion)
    assert "improves_on_champion" in report.failures
