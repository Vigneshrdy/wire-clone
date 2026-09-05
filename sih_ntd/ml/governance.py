"""Promotion gates.

Programmatic checks that a candidate must clear before it is *allowed* to be
promoted. Clearing them is necessary, not sufficient: promotion is still an
explicit action (CLI or API) so a human decides. That split is the whole point --
automatic promotion from a metric threshold is how a poisoned or overfitted model
reaches production.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Settings, get_settings
from ..schemas import FEATURE_SCHEMA_VERSION, ModelMetadata


@dataclass
class GateReport:
    passed: bool
    results: dict[str, bool] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)
    #: Gates that failed but were explicitly acknowledged by an operator. Recorded
    #: so an override is visible in the promotion history forever.
    acknowledged: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "results": self.results,
            "failures": self.failures,
            "acknowledged": self.acknowledged,
        }


class PromotionGate:
    """Evaluates a candidate against thresholds, schema and the incumbent."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.config = self.settings.registry

    def evaluate(
        self,
        candidate: ModelMetadata,
        champion: ModelMetadata | None = None,
        *,
        regression_tests_passed: bool | None = None,
        acknowledge: set[str] | None = None,
    ) -> GateReport:
        """Run every gate.

        ``acknowledge`` names gates an operator has explicitly accepted as failing
        -- the lab-data case, where ``not_implausibly_perfect`` fires because the
        training corpus is synthetic and separable by construction. Acknowledged
        gates do not block, but they are reported and stored in the promotion
        record, so "we knew and decided anyway" stays auditable. They are never
        acknowledged by default.
        """
        results: dict[str, bool] = {}
        failures: dict[str, str] = {}

        def check(name: str, ok: bool, message: str) -> None:
            results[name] = ok
            if not ok:
                failures[name] = message

        metrics = candidate.metrics
        precision = metrics.get("precision")
        recall = metrics.get("recall")
        fpr = metrics.get("false_positive_rate")
        latency = metrics.get("inference_latency_ms")

        check(
            "precision", precision is not None and precision >= self.config.min_precision,
            f"precision {precision} < required {self.config.min_precision}",
        )
        check(
            "recall", recall is not None and recall >= self.config.min_recall,
            f"recall {recall} < required {self.config.min_recall}",
        )
        check(
            "false_positive_rate",
            fpr is not None and fpr <= self.config.max_false_positive_rate,
            f"false-positive rate {fpr} > allowed {self.config.max_false_positive_rate}",
        )
        check(
            "inference_latency",
            latency is not None and latency <= self.config.max_inference_latency_ms,
            f"inference latency {latency} ms > allowed "
            f"{self.config.max_inference_latency_ms} ms",
        )
        check(
            "feature_schema",
            candidate.feature_schema_version == FEATURE_SCHEMA_VERSION,
            f"model was trained on feature schema {candidate.feature_schema_version}, "
            f"runtime is {FEATURE_SCHEMA_VERSION}",
        )
        check(
            "artifact_integrity",
            bool(candidate.artifact_hash) and len(candidate.artifact_hash) == 64,
            "artifact hash missing or malformed",
        )
        if self.config.require_dataset:
            check(
                "dataset_recorded", bool(candidate.dataset_id),
                "no dataset_id recorded; a model with unknown provenance cannot be promoted",
            )
        if regression_tests_passed is not None:
            check(
                "regression_tests", regression_tests_passed,
                "detector regression tests did not pass for this candidate",
            )
        if champion is not None and self.config.require_champion_improvement:
            champion_f1 = champion.metrics.get("f1", 0.0)
            candidate_f1 = metrics.get("f1", 0.0)
            check(
                "improves_on_champion", candidate_f1 >= champion_f1,
                f"candidate F1 {candidate_f1:.4f} does not beat champion "
                f"{champion_f1:.4f}",
            )
        # Transfer check: does the model still fire on random names from a
        # generator that had no part in the training corpus? A model that scores
        # perfectly in-distribution and zero out-of-distribution has memorised its
        # training generators, which is the single most likely failure mode for a
        # lexical DGA model trained on synthetic data.
        transfer_recall = metrics.get("independent_generator_recall")
        if transfer_recall is not None:
            check(
                "generalises_to_independent_generator",
                transfer_recall >= self.config.min_transfer_recall,
                f"only {transfer_recall:.0%} of out-of-corpus DGA probe names were "
                f"detected (need {self.config.min_transfer_recall:.0%}); the model has "
                "memorised its training generators rather than learning randomness",
            )
        transfer_fpr = metrics.get("independent_benign_fpr")
        if transfer_fpr is not None:
            check(
                "independent_benign_fpr",
                transfer_fpr <= self.config.max_false_positive_rate * 5,
                f"out-of-corpus benign probe false-positive rate {transfer_fpr:.2f} is "
                "too high",
            )
        # Sanity check against label poisoning / leakage: a perfect score on a
        # security dataset is far more likely to be a bug than a breakthrough.
        check(
            "not_implausibly_perfect",
            not (precision == 1.0 and recall == 1.0),
            "precision and recall are both exactly 1.0; suspect label leakage or a "
            "trivially separable dataset -- review before promotion",
        )
        acknowledged_names = set(acknowledge or ())
        acknowledged = {
            name: reason for name, reason in failures.items() if name in acknowledged_names
        }
        blocking = {
            name: reason for name, reason in failures.items() if name not in acknowledged_names
        }
        return GateReport(
            passed=not blocking, results=results, failures=blocking, acknowledged=acknowledged
        )
