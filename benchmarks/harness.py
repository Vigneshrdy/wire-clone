"""Throughput and latency harness.

Measures the in-process path (generator -> features -> detectors -> fusion ->
alerts) because that is where the CPU cost lives; Redis round-trip is measured
separately by ``--with-stream``.

Every result records hardware, sample size, configuration and model versions, and
is written to the ``benchmarks`` table so ``GET /api/v1/benchmarks`` can serve it.
Nothing here fabricates a number: if a stage was not run, its field is absent.
"""

from __future__ import annotations

import platform
import time

from sih_ntd.config import get_settings
from sih_ntd.detectors import build_default_registry
from sih_ntd.features.engine import FeatureEngine
from sih_ntd.metrics import FEATURE_LATENCY, FUSION_LATENCY, INFERENCE_LATENCY
from sih_ntd.pipeline import Pipeline
from sih_ntd.schemas import BenchmarkResult, DetectorState
from sih_ntd.sensor.synthetic import generate
from sih_ntd.store import Store
from sih_ntd.windows import quantile


def hardware_description() -> str:
    try:
        import os

        cpus = os.cpu_count() or 0
    except Exception:  # noqa: BLE001
        cpus = 0
    return f"{platform.platform()} | python {platform.python_version()} | {cpus} logical CPUs"


def run_benchmark(
    *,
    scenario: str = "mixed",
    count: int = 20_000,
    seed: int = 1337,
    persist: bool = True,
    store: Store | None = None,
) -> BenchmarkResult:
    """Run one measured pass and return a :class:`BenchmarkResult`."""
    settings = get_settings()
    store = store if store is not None else Store(settings=settings)
    events = generate(scenario, count=count, seed=seed)

    pipeline = Pipeline(
        settings,
        store=store,
        publish_alerts=False,
        detectors=build_default_registry(settings),
        engine=FeatureEngine(settings),
    )
    started = time.perf_counter()
    stats = pipeline.handle_events(events, persist=persist)
    elapsed = time.perf_counter() - started

    latencies = sorted(stats.latencies_ms)
    detector_versions = {
        d.name: (d.model_version or f"{d.technique}:{d.version}")
        for d in pipeline.detectors
        if d.state() is DetectorState.READY
    }
    result = BenchmarkResult(
        name=f"in_process/{scenario}",
        events=stats.events,
        duration_seconds=elapsed,
        events_per_second=stats.events / elapsed if elapsed > 0 else 0.0,
        latency_p50_ms=quantile(latencies, 0.5) if latencies else None,
        latency_p95_ms=quantile(latencies, 0.95) if latencies else None,
        latency_p99_ms=quantile(latencies, 0.99) if latencies else None,
        latency_max_ms=latencies[-1] if latencies else None,
        stage_seconds={
            # Histogram sums: total wall time attributed to each stage.
            "feature_engine": _hist_sum(FEATURE_LATENCY),
            "detector_inference": _hist_sum(INFERENCE_LATENCY),
            "fusion": _hist_sum(FUSION_LATENCY),
        },
        alerts_generated=stats.alerts,
        hardware=hardware_description(),
        configuration={
            "windows": ",".join(str(w) for w in settings.windows.sizes),
            "emit_interval_seconds": str(settings.windows.emit_interval_seconds),
            "persist": str(persist),
            "persist_features": str(settings.store.persist_features),
            "feature_vectors": str(stats.features),
            "detector_results": str(stats.detector_results),
            "suppressed_duplicates": str(stats.suppressed),
        },
        model_versions=detector_versions,
        dataset=f"synthetic:{scenario}:seed={seed}:events={count}",
    )
    store.insert_benchmark(result)
    return result


def _hist_sum(histogram) -> float:
    return float(sum(histogram._sums.values()))


if __name__ == "__main__":
    import json

    print(json.dumps(run_benchmark().model_dump(mode="json"), indent=2, default=str))
