# Architecture

## Data flow

```
UNTRUSTED SOURCES
  live TAP / SPAN / data diode | historical PCAP | Zeek JSON | NetFlow / IPFIX / sFlow
  synthetic lab generator
        |
        v
PASSIVE SENSOR LAYER                          sih_ntd/sensor/
  zeek_reader.py   Zeek conn/dns/ssl JSON, correlated by uid
  replay.py        PCAP -> Zeek -> events (Zeek is a host dependency)
  synthetic.py     seeded generator: benign + 7 attack patterns
        |
        v
EVENT NORMALIZATION                           sih_ntd/ingest.py
  alias-table field mapping -> NormalizedEvent v1
  aggressive validation, deterministic event_id, bounded dedup memory
        |
        v
STREAMING EVENT FABRIC (Redis Streams)        sih_ntd/streaming.py
  network.raw  network.normalized  network.features
  network.alerts  network.feedback  model.events   + <stream>.dlq
  consumer groups, ack-after-persist, XAUTOCLAIM reclaim, poison -> DLQ
        |
        +------------------------------+
        v                              v
STREAMING FEATURE ENGINE          ANALYTICAL STORE            sih_ntd/store.py
  windows.py    SlidingWindow,     events, features,
                UniqueTracker,     detector_results, alerts,
                IntervalTracker,   alert_events (append-only),
                LruStateMap        incidents, feedback,
  features/     stats.py (pure),   drift_events, benchmarks
                engine.py
  1s/5s/30s/60s/300s, all in one vector per entity
        |
        v
BEHAVIOURAL BASELINE ENGINE                   sih_ntd/baselines.py
  EWMA mean/variance + 256-sample quantile reservoir
  keyed (entity_kind, entity_id, metric); explicit cold start
        |
        v
SPECIALISED DETECTION MESH                    sih_ntd/detectors/
  base.py  one contract, one registry, per-detector fault isolation
  ddos  recon  c2  dns_tunnel  exfiltration       (READY)
  dga  tls_malware                               (UNAVAILABLE, honest)
        |
        v
THREAT FUSION                                 sih_ntd/fusion.py
  duplicate suppression -> cross-detector corroboration -> incident grouping
  confidence combination (bounded, documented), severity scored separately
        |
        v
EVIDENCE / LINEAGE                            sih_ntd/evidence.py
  observations vs baseline comparisons, reason codes, detector contributions,
  detector + model + feature-schema versions, flow and PCAP references
        |
        v
ALERT (schemas.Alert v1)  ->  store  +  Redis network.alerts
        |
        +------------------------------+
        v                              v
FASTAPI              sih_ntd/api.py       AUDIT TRAIL
  REST /api/v1/*, WS /ws/alerts             alert_events + detector_results
  /health /ready /metrics                   + registry promotion history
        |
        v
ANALYST FEEDBACK -> DRIFT ENGINE -> TRAINING DATA FACTORY -> OFFLINE TRAINING
  -> CHAMPION vs CHALLENGER -> GOVERNANCE GATES -> REGISTRY -> SHADOW EVAL
  -> EXPLICIT PROMOTION (reversible)          sih_ntd/ml/
```

## Component responsibilities

| Module | Responsibility | Notable decision |
|---|---|---|
| `schemas.py` | every cross-boundary type, versioned | `extra="forbid"` everywhere; detector results and alerts are frozen |
| `config.py` | all thresholds in one place | no magic numbers in detectors; `SIH_*` env overrides |
| `windows.py` | the only time-window implementation | `rate()` divides by window size, not observed span; `coverage()` exposes cold windows |
| `features/stats.py` | pure statistics | stateless and deterministic, shared by training and inference |
| `features/engine.py` | event -> feature vectors | one vector per entity carrying *all* window sizes |
| `baselines.py` | per-entity EWMA baselines | cold baseline returns `None`, never a large z-score |
| `detectors/base.py` | the detector contract | `safe_evaluate` isolates faults; `UNAVAILABLE` is a first-class state |
| `fusion.py` | correlation, dedup, severity | detector results immutable; fusion creates new records |
| `store.py` | the only module that knows SQL | single seam for a ClickHouse migration |
| `ml/` | dataset factory, training, registry, gates, drift, shadow | nothing here can promote a model |

## Why one feature vector carries every window

`flows_per_sec_1s` through `flows_per_sec_300s` all live in the same
`FeatureVector`. The alternative — one vector per window size — multiplies object
count by five on the hot path and forces a detector to join across vectors to
compare a 1-second burst against a 300-second baseline. The cost is that the
feature contract lives in `FEATURE_SCHEMA_VERSION` plus
`windowed_feature_names()` rather than in the type system; `FeatureVector.require()`
turns a missing feature into a loud `KeyError` instead of a silent `0.0`.

## Three entity perspectives

The same flow is evidence of different things depending on which end you look
from, so the engine keeps three keyed states:

- `HOST` (source IP) — fan-out, scanning, DNS behaviour, egress volume
- `DESTINATION` (destination IP) — inbound flood concentration, source entropy
- `PAIR` (`src->dst`) — beacon periodicity, payload stability

Alert attribution follows the same rule (`evidence.subject_of`): a flood is
attributed to the *target*, everything else to the source. Attributing a flood to
one of 250 spoofed sources would both mis-word the alert and scatter one incident
across hundreds of subjects.

## Storage: SQLite now, ClickHouse later

The brief prefers ClickHouse. The prototype uses SQLite in WAL mode, and
`store.py` is the only module containing SQL.

Reasoning: every table here is append-mostly with time-ordered reads, volumes are
in the millions of rows, and the demo has to run offline on a laptop. A ClickHouse
container would add a service, a driver dependency and CI complexity while
changing no caller. Phase 12 replaces the bodies of `store.py`'s methods; nothing
above it moves. The migration is a real plan, not a deferral: the schema in
`store.py` already avoids row-level updates except on the `alerts` table, and even
those are mirrored into the append-only `alert_events` table.

## Backpressure and failure

| Failure | Behaviour |
|---|---|
| Malformed event | validated, rejected, counted by low-cardinality reason, dead-lettered on the stream path |
| Detector raises | caught per detector, counted, other detectors still see the window |
| Detector has no model | reports `UNAVAILABLE` with a reason; returns nothing |
| Redis unreachable | `StreamUnavailable` after bounded retries — no infinite loop |
| Store write fails | transaction rolls back and re-raises; stream entries stay unacked and are retried |
| Poison stream entry | after `max_deliveries` attempts, moved to `<stream>.dlq` and acked |
| Unbounded entity growth | `LruStateMap` evicts least-recently-seen entities and counts evictions |
| Stream goes quiet mid-burst | `Pipeline.flush_open_windows()` closes open windows so a trailing burst is still evaluated |

That last row was a real bug: the worker only saw features that the engine emitted
on its 1-second tick, so a 1-second flood arriving at the end of a replay produced
features no detector ever evaluated. An integration test caught it.

## Streams and retention

`XADD ... MAXLEN ~ 100000` per stream (approximate trimming is O(1), exact is not).
Consumer groups start at `0` with `mkstream`, so a consumer can be started before
any producer exists. Acknowledgement happens *after* the batch is persisted.
