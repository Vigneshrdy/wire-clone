"""The detection pipeline: events in, alerts out.

Two entry points over the same code:

* :meth:`Pipeline.handle_events` -- synchronous, in-process. Used by PCAP replay,
  benchmarks and tests, where determinism matters more than decoupling.
* :meth:`Pipeline.run_worker` -- consumes ``network.normalized`` from Redis with a
  consumer group, so ingestion and detection can scale and fail independently.

Both paths call :meth:`Pipeline.process_event`, so there is exactly one definition
of what the pipeline does.

Failure policy
--------------
A malformed event is rejected and counted (never coerced to zeros). A detector
that raises is isolated by :func:`sih_ntd.detectors.base.safe_evaluate` and the
window continues through the other detectors. A store write failure aborts that
batch's transaction and re-raises, leaving the Redis entries unacked so the batch
is retried rather than silently dropped.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from .config import Settings, Streams, get_settings
from .detectors import DetectorRegistry, build_default_registry
from .errors import ValidationRejection
from .features.engine import FeatureEngine
from .fusion import FusionOutcome, ThreatFusion
from .logging_conf import get_logger
from .metrics import (
    FEATURE_LATENCY,
    FEATURES_GENERATED,
    FUSION_LATENCY,
    PIPELINE_LATENCY,
    TRACKED_ENTITIES,
)
from .schemas import Alert, DetectorResult, FeatureVector, NormalizedEvent, SourceType
from .store import Store
from .streaming import StreamClient
from .windows import window_suffix

log = get_logger(__name__)


@dataclass
class PipelineStats:
    """Counters for one run. Also the source of benchmark numbers."""

    events: int = 0
    rejected: int = 0
    features: int = 0
    detector_results: int = 0
    shadow_results: int = 0
    alerts: int = 0
    suppressed: int = 0
    incidents: int = 0
    latencies_ms: list[float] = field(default_factory=list, repr=False)

    def merge(self, other: "PipelineStats") -> None:
        self.events += other.events
        self.rejected += other.rejected
        self.features += other.features
        self.detector_results += other.detector_results
        self.shadow_results += other.shadow_results
        self.alerts += other.alerts
        self.suppressed += other.suppressed
        self.incidents += other.incidents
        self.latencies_ms.extend(other.latencies_ms)


class Pipeline:
    """Feature engine + detection mesh + fusion + persistence, wired together."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        store: Store | None = None,
        stream: StreamClient | None = None,
        detectors: DetectorRegistry | None = None,
        engine: FeatureEngine | None = None,
        fusion: ThreatFusion | None = None,
        run_id: str | None = None,
        publish_alerts: bool = True,
    ) -> None:
        self.settings = settings or get_settings()
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.store = store if store is not None else Store(settings=self.settings)
        self.stream = stream
        self.publish_alerts = publish_alerts
        self.detectors = detectors or build_default_registry(self.settings)
        self.engine = engine or FeatureEngine(self.settings)
        self.fusion = fusion or ThreatFusion(self.settings, pipeline_run_id=self.run_id)
        self.stats = PipelineStats()
        self.alerts: list[Alert] = []
        # True when events have been processed since the last window flush, so an
        # idle stream is only closed out once.
        self._pending_flush = False

    # --- core ------------------------------------------------------------
    def process_event(self, event: NormalizedEvent) -> tuple[list[FeatureVector], list[DetectorResult], FusionOutcome]:
        """One event -> features -> detector results -> fusion outcome."""
        started = time.perf_counter()
        vectors = self.engine.process(event)
        FEATURE_LATENCY.observe(time.perf_counter() - started)
        for vector in vectors:
            FEATURES_GENERATED.inc(window=window_suffix(vector.window_seconds))

        results: list[DetectorResult] = []
        for vector in vectors:
            results.extend(self.detectors.evaluate(vector))
            results.extend(self._shadow(vector))

        fusion_started = time.perf_counter()
        outcome = self.fusion.ingest(results)
        FUSION_LATENCY.observe(time.perf_counter() - fusion_started)
        PIPELINE_LATENCY.observe(time.perf_counter() - started)
        return vectors, results, outcome

    def _shadow(self, vector: FeatureVector) -> list[DetectorResult]:
        """Score challengers alongside champions, for offline comparison only.

        Shadow results are persisted and never enter fusion (``ThreatFusion.ingest``
        drops them), which is the mechanism that stops a challenger from creating
        production alerts.
        """
        out: list[DetectorResult] = []
        for detector in self.detectors:
            shadow_fn = getattr(detector, "shadow_evaluate", None)
            if shadow_fn is None:
                continue
            from .schemas import DetectorInput

            try:
                result = shadow_fn(DetectorInput(features=vector, timestamp=vector.timestamp))
            except Exception:  # noqa: BLE001 -- shadow must never affect production
                continue
            if result is not None:
                out.append(result)
        return out

    def flush_open_windows(self, *, persist: bool = True) -> PipelineStats:
        """Evaluate every tracked entity's current windows and emit any alerts.

        Called when the input stream goes quiet. Without this, a burst that ends
        just before the next emit tick is never evaluated: the feature engine only
        emits once per entity per ``emit_interval_seconds``, so a 1-second flood
        arriving at the end of a replay would produce features that no detector ever
        saw. Found by an integration test, not by inspection.
        """
        stats = PipelineStats()
        if not self._pending_flush:
            return stats
        vectors = self.engine.flush()
        results: list[DetectorResult] = []
        for vector in vectors:
            batch = self.detectors.evaluate(vector)
            results.extend(batch)
            stats.detector_results += len(batch)
            self._apply_outcome(self.fusion.ingest(batch), self.alerts, stats, persist=persist)
        stats.features += len(vectors)
        if persist:
            self._persist([], vectors, results)
        self._pending_flush = False
        self.stats.merge(stats)
        return stats

    def handle_events(
        self, events: Iterable[NormalizedEvent], *, persist: bool = True, flush: bool = True
    ) -> PipelineStats:
        """Run a bounded batch of events through the pipeline synchronously."""
        stats = PipelineStats()
        self._pending_flush = True
        event_buffer: list[NormalizedEvent] = []
        vector_buffer: list[FeatureVector] = []
        result_buffer: list[DetectorResult] = []
        alerts: list[Alert] = []
        last_ts = 0.0

        for event in events:
            started = time.perf_counter()
            vectors, results, outcome = self.process_event(event)
            stats.latencies_ms.append((time.perf_counter() - started) * 1000.0)
            stats.events += 1
            stats.features += len(vectors)
            stats.detector_results += len(results)
            stats.shadow_results += sum(1 for r in results if r.shadow)
            last_ts = max(last_ts, event.epoch)
            event_buffer.append(event)
            vector_buffer.extend(vectors)
            result_buffer.extend(results)
            self._apply_outcome(outcome, alerts, stats, persist=persist)
            if persist and len(event_buffer) >= 500:
                self._persist(event_buffer, vector_buffer, result_buffer)
                event_buffer, vector_buffer, result_buffer = [], [], []

        if flush:
            # Close out short captures: see FeatureEngine.flush.
            self._pending_flush = False
            for vector in self.engine.flush(last_ts or None):
                vector_buffer.append(vector)
                results = self.detectors.evaluate(vector)
                result_buffer.extend(results)
                stats.detector_results += len(results)
                self._apply_outcome(self.fusion.ingest(results), alerts, stats, persist=persist)

        if persist:
            self._persist(event_buffer, vector_buffer, result_buffer)
        TRACKED_ENTITIES.set(self.engine.tracked_entities, kind="all")
        self.stats.merge(stats)
        self.alerts.extend(a for a in alerts if a not in self.alerts)
        return stats

    def _apply_outcome(
        self, outcome: FusionOutcome, alerts: list[Alert], stats: PipelineStats, *, persist: bool
    ) -> None:
        if outcome.alerts:
            alerts.extend(outcome.alerts)
            stats.alerts += len(outcome.alerts)
            if persist:
                self.store.insert_alerts(outcome.alerts)
            if self.publish_alerts and self.stream is not None:
                self.stream.publish_many(
                    Streams.ALERTS, [a.model_dump(mode="json") for a in outcome.alerts]
                )
        for touch in outcome.touches:
            stats.suppressed += 1
            if persist:
                self.store.touch_alert(
                    touch.alert_id, touch.last_seen, touch.dedup_count, touch.event_count
                )
        if outcome.incidents:
            stats.incidents += len(outcome.incidents)
            if persist:
                self.store.upsert_incidents(outcome.incidents)

    def _persist(
        self,
        events: list[NormalizedEvent],
        vectors: list[FeatureVector],
        results: list[DetectorResult],
    ) -> None:
        if events:
            self.store.insert_events(events)
        if vectors:
            self.store.insert_features(vectors)
        if results:
            self.store.insert_detector_results(results)

    # --- worker ----------------------------------------------------------
    def run_worker(self, *, max_batches: int | None = None, idle_exit: bool = False) -> PipelineStats:
        """Consume ``network.normalized`` until stopped.

        Events are acknowledged only after their batch has been persisted, so a
        crash mid-batch means redelivery rather than data loss.
        """
        if self.stream is None:
            self.stream = StreamClient(self.settings)
        self.stream.require()
        self.stream.ensure_group(Streams.NORMALIZED)
        batches = 0
        idle = 0
        while max_batches is None or batches < max_batches:
            batch = self.stream.read(Streams.NORMALIZED)
            if not batch:
                batch = self.stream.reclaim(Streams.NORMALIZED)
            if not batch:
                # Stream is quiet: close out any open windows so a burst at the end
                # of a replay is still evaluated.
                self.flush_open_windows()
                idle += 1
                if idle_exit and idle >= 2:
                    break
                continue
            idle = 0
            batches += 1
            message_ids: list[str] = []
            events: list[NormalizedEvent] = []
            for message_id, payload in batch:
                try:
                    events.append(NormalizedEvent.model_validate(payload))
                    message_ids.append(message_id)
                except Exception as exc:  # noqa: BLE001 -- untrusted stream payload
                    self.stats.rejected += 1
                    self.stream.dead_letter(
                        Streams.NORMALIZED, message_id, {"payload": payload}, f"invalid event: {exc}"
                    )
            if events:
                events.sort(key=lambda e: e.epoch)
                self.handle_events(events, persist=True, flush=False)
            self.stream.ack(Streams.NORMALIZED, message_ids)
            self.stream.lag(Streams.NORMALIZED)
        self.flush_open_windows()
        return self.stats


def publish_events(
    events: Iterable[NormalizedEvent], stream: StreamClient | None = None, batch_size: int = 500
) -> int:
    """Push normalized events onto ``network.normalized`` for the worker to consume."""
    stream = stream or StreamClient()
    stream.require()
    published = 0
    batch: list[dict] = []
    for event in events:
        batch.append(event.model_dump(mode="json"))
        if len(batch) >= batch_size:
            published += stream.publish_many(Streams.NORMALIZED, batch)
            batch = []
    if batch:
        published += stream.publish_many(Streams.NORMALIZED, batch)
    return published


def normalize_records(
    records: Iterable[dict], source_type: SourceType, settings: Settings | None = None
) -> Iterator[NormalizedEvent]:
    """Convenience wrapper used by the CLI replay path."""
    normalizer = Normalizer(settings)
    for record in records:
        try:
            event = normalizer.normalize(record, source_type)
        except ValidationRejection:
            continue
        if not normalizer.is_duplicate(event.event_id):
            yield event
