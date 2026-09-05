# Benchmarking

## Rule

No number in this repository is estimated, extrapolated or aspirational. Every
figure below came from `uv run sih-ntd bench` on the hardware named next to it. If a
stage did not run, its field is absent rather than filled in.

## Running

```bash
uv run sih-ntd bench --scenario mixed --count 20000
uv run sih-ntd bench --scenario ddos_syn --count 50000
SIH_STORE__PERSIST_FEATURES=false uv run sih-ntd bench --count 20000 --no-persist
```

Results are written to the `benchmarks` table and served by
`GET /api/v1/benchmarks`.

`--count` is the *scenario* size; `mixed` overlays benign traffic with every attack
pattern, so the emitted event count is larger (20 000 → 121 664).

## Measured results

Hardware: `Linux-7.1.6-arch1-1-x86_64-with-glibc2.44`, Python 3.12.13,
12 logical CPUs. Single process, single worker. Dataset:
`synthetic:mixed:seed=1337`, 121 664 events, 5 detectors READY
(`dga` and `tls_malware` are UNAVAILABLE and were not scored).

| Configuration | Events/sec | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| full persistence | 1 584 | 0.150 ms | 1.36 ms | 2.05 ms | 572 ms |
| detection only, no persistence | 1 955 | 0.155 ms | 1.33 ms | 2.04 ms | — |

Stage attribution at full persistence, of 76.8 s wall time:

| Stage | Seconds | Share |
|---|---|---|
| feature engine | 51.5 | 67 % |
| fusion | 2.45 | 3 % |
| detector inference | 0.49 | 0.6 % |
| persistence + generation + overhead | ~22.4 | 29 % |

Volumes in that run: 120 560 feature vectors, 9 332 detector results, 14 alerts,
8 050 suppressed duplicates.

DGA model inference latency, measured single-row (`evaluate_classifier`):
**1.0–2.4 ms** per `predict_proba` call depending on the estimator built. Cross-
validated calibration (`cv=3`) measured ~7.9 ms and breached the 5 ms promotion
gate, which is why calibration is fitted prefit on a frozen estimator.

## Reading these numbers

**The feature engine dominates, not the detectors.** Detector inference is 0.6 % of
wall time. Optimisation effort belongs in `features/engine.py` — specifically the
five `WindowBundle` objects maintained per entity per event across three entity
perspectives.

**The p99/max gap is real.** 2.05 ms p99 against a 572 ms max: the max is a
persistence flush (500-event batches) plus SQLite WAL checkpointing. It is a
throughput artefact, not per-event detection latency.

**One process.** Redis Streams consumer groups distribute entries across workers, so
horizontal scaling is available but was not measured. Do not multiply these numbers
by core count and quote the result.

**Synthetic events.** Generated metadata, not a real capture. Real Zeek output has
different field density and cardinality. Re-measure against your own PCAP before
quoting a capacity figure.

## What is not measured yet

Recorded honestly as gaps rather than guessed:

- Redis round-trip throughput (publish → consume → ack) as a separate figure
- multi-worker scaling
- throughput against real Zeek logs from a real capture
- Mbps — the synthetic generator produces flow metadata, not packet volume, so a
  line-rate figure would be fabricated
- memory and CPU ceilings under sustained load
- `ClickHouse` comparison (the store is SQLite in this prototype)

## Methodology

`benchmarks/harness.py`:

1. Generate a seeded scenario (deterministic, so runs are comparable).
2. Run it through the real `Pipeline` — the same code path the worker uses.
3. Record per-event wall-clock latency for every event.
4. Report p50/p95/p99/max from the sorted sample, plus histogram stage sums.
5. Record hardware, sample size, duration, configuration and the model version of
   every READY detector.
6. Persist to the `benchmarks` table.

Latency is measured per event through `process_event`, which covers feature
generation, every detector, and fusion.
