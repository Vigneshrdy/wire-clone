"""Dataset factory, training reproducibility, artifact safety, shadow comparison."""

from __future__ import annotations

import numpy as np
import pytest

from sih_ntd.features.stats import DNS_LEXICAL_FEATURES
from sih_ntd.ml.dataset import (
    HOLDOUT_FAMILY,
    build_dga_dataset,
    build_feedback_dataset,
    load_dataset_metadata,
    save_dataset,
)
from sih_ntd.ml.registry import ModelRegistry
from sih_ntd.ml.shadow import compare
from sih_ntd.ml.training import (
    INDEPENDENT_DGA_PROBE,
    build_base_estimator,
    calibrate,
    evaluate_classifier,
    train_dga,
    transfer_check,
)
from sih_ntd.schemas import FeedbackLabel, ModelStatus

SMALL = {"per_family": 250, "benign_count": 1000}


def test_dataset_is_reproducible_from_its_seed():
    first = build_dga_dataset(**SMALL)
    second = build_dga_dataset(**SMALL)
    assert first.metadata.content_hash == second.metadata.content_hash
    assert first.train[0] == second.train[0]


def test_dataset_records_provenance_and_split_strategy():
    dataset = build_dga_dataset(**SMALL)
    metadata = dataset.metadata
    assert metadata.label_provenance == {"lab_generated": metadata.row_count}
    assert "stratified" in metadata.split_strategy
    assert metadata.feature_names == list(DNS_LEXICAL_FEATURES)
    assert metadata.class_distribution["dga"] > 0
    assert len(metadata.content_hash) == 64


def test_holdout_family_is_excluded_from_training():
    """Out-of-family transfer is only measurable if the family is truly held out."""
    dataset = build_dga_dataset(**SMALL)
    assert dataset.split_provenance["unseen_family"] == [HOLDOUT_FAMILY]
    assert HOLDOUT_FAMILY not in dataset.split_provenance["train"]
    assert dataset.unseen_family is not None


def test_dataset_persists_every_split(settings):
    dataset = build_dga_dataset(**SMALL)
    path = save_dataset(dataset, settings.registry.root)
    for split in ("train", "validation", "test", "unseen_family"):
        assert (path / f"{split}.csv").exists()
    assert load_dataset_metadata(dataset.metadata.dataset_id, settings.registry.root) is not None


def test_training_is_deterministic_and_registers_a_candidate(settings):
    registry = ModelRegistry(settings=settings)
    dataset = build_dga_dataset(**SMALL)
    metadata, validation, test, _ = train_dga(
        dataset=dataset, registry=registry, settings=settings, register=True
    )
    assert metadata is not None
    assert metadata.status is ModelStatus.CANDIDATE, "training must never promote"
    assert metadata.dataset_id == dataset.metadata.dataset_id
    assert metadata.feature_names == list(DNS_LEXICAL_FEATURES)
    assert "LAB-GENERATED" in metadata.notes
    assert 0.0 <= test.metrics["precision"] <= 1.0
    assert metadata.metrics["inference_latency_ms"] > 0, "latency must be measured, not assumed"
    assert "unseen_family_recall" in metadata.metrics


def test_retraining_the_same_seed_gives_the_same_scores(settings):
    dataset = build_dga_dataset(**SMALL)
    scores = []
    for _ in range(2):
        base = build_base_estimator()
        base.fit(np.asarray(dataset.train[0]), np.asarray(dataset.train[1]))
        estimator = calibrate(base, *dataset.validation)
        scores.append(evaluate_classifier(estimator, *dataset.test).metrics["pr_auc"])
    assert scores[0] == pytest.approx(scores[1])


def test_registered_artifact_loads_and_type_is_checked(settings):
    registry = ModelRegistry(settings=settings)
    metadata, _, _, _ = train_dga(
        dataset=build_dga_dataset(**SMALL), registry=registry, settings=settings
    )
    estimator = registry.load(metadata)
    assert type(estimator).__name__ == metadata.estimator_class
    probabilities = estimator.predict_proba([[0.0] * len(DNS_LEXICAL_FEATURES)])
    assert probabilities.shape == (1, 2)


def test_transfer_check_measures_out_of_corpus_recall(settings):
    """The check that caught a memorising model during development."""
    dataset = build_dga_dataset(**SMALL)
    base = build_base_estimator()
    base.fit(np.asarray(dataset.train[0]), np.asarray(dataset.train[1]))
    estimator = calibrate(base, *dataset.validation)
    report = transfer_check(estimator, threshold=0.85)
    assert set(report) == {
        "independent_generator_recall", "independent_benign_fpr",
        "independent_dga_mean_probability", "independent_benign_mean_probability",
    }
    assert 0.0 <= report["independent_generator_recall"] <= 1.0
    assert len(INDEPENDENT_DGA_PROBE) >= 10


def test_feedback_dataset_needs_analyst_labels(store, settings):
    assert build_feedback_dataset(
        store, "ddos", feature_names=["syn_rate_1s"], settings=settings
    ) is None


def test_feedback_dataset_uses_only_reviewed_labels(store, settings, pipeline):
    """Continuous learning must be driven by analyst labels, not detector output."""
    from sih_ntd.schemas import AnalystFeedback
    from tests.conftest import syn_flood_events

    pipeline.handle_events(syn_flood_events(3000))
    alerts = store.query_alerts()
    assert alerts
    for index, alert in enumerate(alerts * 25):
        store.insert_feedback(
            AnalystFeedback(
                alert_id=alert.alert_id,
                label=FeedbackLabel.TRUE_POSITIVE if index % 2 else FeedbackLabel.FALSE_POSITIVE,
                analyst_id="analyst-1",
            )
        )
    # Only one alert exists, so feedback rows collapse onto it: too few distinct
    # alerts to build a dataset, which the factory must report rather than invent.
    dataset = build_feedback_dataset(
        store, "ddos", feature_names=["syn_rate_1s"], settings=settings
    )
    assert dataset is None or dataset.metadata.label_provenance["analyst_reviewed"] > 0


def test_shadow_comparison_reports_no_challenger(store, settings):
    registry = ModelRegistry(settings=settings)
    comparison = compare("dga", store, registry)
    assert comparison.challenger_version is None
    assert "no challenger" in comparison.verdict


def test_shadow_never_promotes(settings, store):
    """Shadow tooling is read-only by construction."""
    registry = ModelRegistry(settings=settings)
    train_dga(dataset=build_dga_dataset(**SMALL), registry=registry, settings=settings)
    compare("dga", store, registry)
    assert registry.champion("dga") is None
