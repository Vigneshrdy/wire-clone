"""Champion vs challenger comparison from recorded shadow inference.

The pipeline scores the challenger on the same feature vectors as the champion and
persists the results with ``shadow = 1``. Nothing here can promote anything; it
produces the comparison an operator reads before deciding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..store import Store
from .drift import population_stability_index
from .registry import ModelRegistry


@dataclass
class ShadowComparison:
    detector: str
    champion_version: str | None
    challenger_version: str | None
    champion_samples: int
    challenger_samples: int
    champion_mean_confidence: float
    challenger_mean_confidence: float
    confidence_psi: float
    champion_metrics: dict[str, float]
    challenger_metrics: dict[str, float]
    verdict: str

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def compare(detector: str, store: Store, registry: ModelRegistry | None = None) -> ShadowComparison:
    """Compare the two models' *offline evaluation* metrics and *live* score spread.

    Evaluation metrics come from the registry (measured on held-out data); the live
    part is only distributional -- without labels for live traffic, a live
    precision comparison would be fiction.
    """
    registry = registry or ModelRegistry()
    champion = registry.champion(detector)
    challenger = registry.challenger(detector)
    live_champion = store.detector_result_scores(detector, shadow=False)
    live_challenger = store.detector_result_scores(detector, shadow=True)

    psi = (
        population_stability_index(live_champion, live_challenger)
        if len(live_champion) >= 20 and len(live_challenger) >= 20
        else 0.0
    )
    verdict = _verdict(champion, challenger, psi)
    return ShadowComparison(
        detector=detector,
        champion_version=champion.model_version if champion else None,
        challenger_version=challenger.model_version if challenger else None,
        champion_samples=len(live_champion),
        challenger_samples=len(live_challenger),
        champion_mean_confidence=(
            sum(live_champion) / len(live_champion) if live_champion else 0.0
        ),
        challenger_mean_confidence=(
            sum(live_challenger) / len(live_challenger) if live_challenger else 0.0
        ),
        confidence_psi=psi,
        champion_metrics=dict(champion.metrics) if champion else {},
        challenger_metrics=dict(challenger.metrics) if challenger else {},
        verdict=verdict,
    )


def _verdict(champion, challenger, psi: float) -> str:
    if challenger is None:
        return "no challenger registered"
    if champion is None:
        return "no champion; challenger cannot be compared and must not be promoted blind"
    champion_f1 = champion.metrics.get("f1", 0.0)
    challenger_f1 = challenger.metrics.get("f1", 0.0)
    champion_fpr = champion.metrics.get("false_positive_rate", 1.0)
    challenger_fpr = challenger.metrics.get("false_positive_rate", 1.0)
    if challenger_f1 > champion_f1 and challenger_fpr <= champion_fpr:
        base = "challenger better on held-out F1 and no worse on false positives"
    elif challenger_f1 > champion_f1:
        base = "challenger better on F1 but worse on false positives -- weigh alert load"
    else:
        base = "challenger does not beat champion; keep the incumbent"
    if psi >= 0.2:
        base += f" (live score distributions differ substantially, PSI={psi:.2f})"
    return base
