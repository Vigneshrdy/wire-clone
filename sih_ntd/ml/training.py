"""Offline training and evaluation.

Design constraints, in order of importance:

1. **Reproducible.** Fixed seed, dataset content hash recorded, artefact hashed.
2. **Honest metrics.** Precision/recall/F1/PR-AUC/ROC-AUC/FPR/FNR, Brier score for
   calibration, and *measured* inference latency. Accuracy is reported but never
   used as the headline: on an imbalanced security dataset it is meaningless.
3. **Streaming-appropriate.** Gradient boosting on 14 lexical features, calibrated
   with isotonic regression on a held-out split, so ``predict_proba`` is a real
   probability the detector can threshold. CPU-only, sub-millisecond per query.
4. **Registered as CANDIDATE.** Training never promotes. Promotion is a separate,
   explicit action that runs the governance gates first.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from ..config import Settings, get_settings
from ..logging_conf import get_logger
from ..schemas import ModelMetadata
from ..features.stats import DNS_LEXICAL_FEATURES, dns_lexical_features
from .dataset import Dataset, build_dga_dataset, save_dataset
from .registry import ModelRegistry

log = get_logger(__name__)
DEFAULT_SEED = 20260905


@dataclass
class Evaluation:
    """Metrics for one model on one split. Every number here is computed, not set."""

    metrics: dict[str, float]
    confusion: dict[str, int]

    def summary(self) -> str:
        m = self.metrics
        return (
            f"precision={m['precision']:.4f} recall={m['recall']:.4f} f1={m['f1']:.4f} "
            f"pr_auc={m['pr_auc']:.4f} roc_auc={m['roc_auc']:.4f} "
            f"fpr={m['false_positive_rate']:.4f} fnr={m['false_negative_rate']:.4f} "
            f"brier={m['brier_score']:.4f} latency={m['inference_latency_ms']:.4f}ms"
        )


def evaluate_classifier(
    estimator: Any,
    rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    *,
    threshold: float = 0.5,
    latency_samples: int = 200,
) -> Evaluation:
    """Compute the full metric set, including a measured per-call latency."""
    X = np.asarray(rows, dtype=float)
    y = np.asarray(labels, dtype=int)
    probabilities = estimator.predict_proba(X)[:, 1]
    predictions = (probabilities >= threshold).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y, predictions, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y, predictions, labels=[0, 1]).ravel()
    # Single-row latency, because that is how inference actually happens in the
    # pipeline -- a batched figure would flatter the number.
    single = X[:1]
    started = time.perf_counter()
    for _ in range(latency_samples):
        estimator.predict_proba(single)
    latency_ms = (time.perf_counter() - started) / latency_samples * 1000.0

    metrics = {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "pr_auc": float(average_precision_score(y, probabilities)) if len(set(y)) > 1 else 0.0,
        "roc_auc": float(roc_auc_score(y, probabilities)) if len(set(y)) > 1 else 0.0,
        "accuracy": float((predictions == y).mean()),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "brier_score": float(brier_score_loss(y, probabilities)),
        "inference_latency_ms": float(latency_ms),
        "positive_rate": float(y.mean()),
        "threshold": float(threshold),
    }
    return Evaluation(
        metrics=metrics, confusion={"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    )


def build_base_estimator(seed: int = DEFAULT_SEED) -> Any:
    """Gradient boosting over the 14 lexical features.

    Boosting handles the non-linear interactions between entropy, length, digit
    ratio and consonant runs that a linear model misses, and stays CPU-only and
    small enough for per-query inference.
    """
    # Modest capacity on purpose: 200 iterations at depth 6 memorised the lab
    # generators, and a memorised model returns 0.0 for random names it has not
    # seen the exact shape of.
    return HistGradientBoostingClassifier(
        max_iter=120, learning_rate=0.08, max_depth=4, l2_regularization=1.0,
        min_samples_leaf=40, random_state=seed, early_stopping=False,
    )


def calibrate(base: Any, rows: Sequence[Sequence[float]], labels: Sequence[int]) -> Any:
    """Wrap a *fitted* model in isotonic calibration fitted on a held-out split.

    Frozen prefit calibration rather than ``cv=3``: cross-validated calibration
    trains three extra boosters and made single-row ``predict_proba`` take ~8 ms,
    which blew the 5 ms promotion gate. This keeps one booster plus one isotonic
    regressor, and the calibration split is genuinely held out because it is the
    validation set. (``FrozenEstimator`` is the sklearn >= 1.6 replacement for the
    removed ``cv="prefit"``.)

    Calibration is what lets the DGA detector publish
    ``CALIBRATED_PROBABILITY`` as its confidence basis instead of inventing a score.
    """
    calibrated = CalibratedClassifierCV(FrozenEstimator(base), method="isotonic")
    calibrated.fit(np.asarray(rows, dtype=float), np.asarray(labels, dtype=int))
    return calibrated


#: Names from a generator that had NO part in building the training corpus, used
#: for the transfer check below. Hand-written on purpose: if the probe came from
#: the same module as the training data, it would measure nothing.
INDEPENDENT_DGA_PROBE: tuple[str, ...] = (
    "kq3x9zvbmwlp.com", "xjdkfjeiruty.net", "ffb1a9c8d7e6f5a4.biz",
    "wmvqbcxzplkrjh.info", "ozjxkvbnmqwe.org", "vhqkzmrtwbnx.com",
    "a7f3k9m2p5q8w1.net", "zxcvbnmasdfghjk.org", "q1w2e3r4t5y6u7i8.info",
    "mlkjhgfdsapoiuy.com", "b4n8x2v6c0z9l5k3.net", "prtwzxqvbnmkljh.org",
)
INDEPENDENT_BENIGN_PROBE: tuple[str, ...] = (
    "cdn.example.com", "api.example.net", "login.example.org", "mail.example.com",
    "d1a2b3c4e5.cdn.example.net", "ec2-54-92-11-3.compute.example-cloud.com",
    "static.example.io", "search.example.com", "video.example.org",
    "checkout.example-shop.com", "img7.assets.example.net", "eu-west-1.example-cloud.com",
)


def transfer_check(estimator: Any, threshold: float) -> dict[str, float]:
    """Score hand-written probe names from outside the training corpus.

    This is the check that caught the real failure during development: a model
    trained on the lab corpus scored a perfect 1.0 on its own held-out split and
    then assigned probability 0.000 to every obviously-random name produced by a
    different generator. In-distribution metrics cannot see that; this can.
    """
    def probabilities(names: tuple[str, ...]) -> np.ndarray:
        rows = np.asarray(
            [[dns_lexical_features(n)[f] for f in DNS_LEXICAL_FEATURES] for n in names],
            dtype=float,
        )
        return estimator.predict_proba(rows)[:, 1]

    dga_probabilities = probabilities(INDEPENDENT_DGA_PROBE)
    benign_probabilities = probabilities(INDEPENDENT_BENIGN_PROBE)
    return {
        "independent_generator_recall": float((dga_probabilities >= threshold).mean()),
        "independent_benign_fpr": float((benign_probabilities >= threshold).mean()),
        "independent_dga_mean_probability": float(dga_probabilities.mean()),
        "independent_benign_mean_probability": float(benign_probabilities.mean()),
    }


def train_dga(
    *,
    dataset: Dataset | None = None,
    seed: int = DEFAULT_SEED,
    registry: ModelRegistry | None = None,
    settings: Settings | None = None,
    per_family: int = 3000,
    benign_count: int = 12000,
    threshold: float | None = None,
    register: bool = True,
) -> tuple[ModelMetadata | None, Evaluation, Evaluation, Dataset]:
    """Train, evaluate and register a DGA candidate. Never promotes.

    Returns ``(metadata, validation_eval, test_eval, dataset)``. The test split is
    an *unseen DGA family*, so the test numbers describe generalisation to a new
    algorithm rather than memorisation of the training generators.
    """
    settings = settings or get_settings()
    registry = registry or ModelRegistry(settings=settings)
    dataset = dataset or build_dga_dataset(seed=seed, per_family=per_family, benign_count=benign_count)
    threshold = threshold if threshold is not None else settings.thresholds.dga_probability

    X_train = np.asarray(dataset.train[0], dtype=float)
    y_train = np.asarray(dataset.train[1], dtype=int)
    started = time.perf_counter()
    base = build_base_estimator(seed)
    base.fit(X_train, y_train)
    # Calibrated on the validation split, which is therefore no longer an unbiased
    # estimate of performance -- test is.
    estimator = calibrate(base, *dataset.validation)
    duration = time.perf_counter() - started

    validation = evaluate_classifier(estimator, *dataset.validation, threshold=threshold)
    test = evaluate_classifier(estimator, *dataset.test, threshold=threshold)
    unseen = (
        evaluate_classifier(estimator, *dataset.unseen_family, threshold=threshold)
        if dataset.unseen_family is not None
        else None
    )
    transfer = transfer_check(estimator, threshold)
    log.info(
        "dga training complete",
        extra={"validation": validation.summary(), "test": test.summary(), "seconds": duration},
    )

    metadata: ModelMetadata | None = None
    if register:
        save_dataset(dataset, settings.registry.root)
        version = registry.next_version(registry.list_models("dga"))
        metadata = registry.register(
            detector="dga",
            model_version=version,
            estimator=estimator,
            feature_names=dataset.feature_names,
            # Registered metrics are the TEST split (unseen family). Using
            # validation numbers here would let the gate pass on a model that only
            # generalises to the family it tuned against.
            metrics={
                **test.metrics,
                **{f"validation_{k}": v for k, v in validation.metrics.items()},
                # Out-of-family transfer, recorded alongside the primary metrics so
                # the known weakness is visible in the registry rather than buried.
                **(
                    {f"unseen_family_{k}": v for k, v in unseen.metrics.items()}
                    if unseen is not None
                    else {}
                ),
                **transfer,
                "training_rows": float(len(y_train)),
            },
            dataset_id=dataset.metadata.dataset_id,
            training_duration_seconds=duration,
            seed=seed,
            notes=(
                "Trained on LAB-GENERATED domains (no external corpus available offline). "
                f"Primary metrics are the held-out test split across families "
                f"{dataset.split_provenance['test']}; unseen_family_* metrics are the "
                f"excluded family {dataset.split_provenance['unseen_family']}. "
                "independent_generator_recall is the fraction of hand-written "
                "out-of-corpus DGA names detected at the configured threshold. "
                "Metrics describe synthetic data and are NOT evidence of field performance."
            ),
        )
    return metadata, validation, test, dataset
