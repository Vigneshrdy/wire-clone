# SIH 26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Passive network threat detection for a monitoring enclave. The system observes
mirrored / unidirectional IP traffic metadata, extracts stateful streaming
features, runs a mesh of specialised detectors, fuses their verdicts into
explainable alerts, and exposes everything over a versioned REST + WebSocket API.

> Observe passively. Detect continuously. Explain every alert. Learn safely.
> Never modify production from untrusted traffic.

The FastAPI backend serves versioned JSON and WebSocket APIs. A separate Next.js
App Router console in `frontend/` provides the analyst workspace at port 3000 and
uses strict same-origin BFF routes to reach FastAPI.

## What works today

| Detector | State | Technique | Evidence it emits |
|---|---|---|---|
| DDoS (SYN / UDP / amplification) | **READY** | rules + baseline | SYN rate vs threshold and baseline, source entropy, unique sources, concentration |
| Recon / port scanning | **READY** | rules | unique ports/hosts, failed-connection ratio, flow durations |
| C2 beaconing | **READY** | statistical | mean/stddev interval, periodicity score, payload stability, destination rarity |
| DNS tunnelling | **READY** | rules + lexical | query length, char entropy, unique-name ratio, TXT ratio, response asymmetry |
| Data exfiltration | **READY** | statistical baseline | outbound bytes, out/in ratio, EWMA z-score, p95 exceedance, destination rarity |
| DGA | **UNAVAILABLE** | supervised | needs a real labelled corpus — see below |
| TLS/QUIC malware | **UNAVAILABLE** | supervised | needs a labelled JA4/JA4S corpus — see below |

The two `UNAVAILABLE` detectors are an honest gap, not a bug. Both would need a
labelled corpus that this repository does not ship and cannot fetch offline. The
full training, evaluation, registry and governance path for them **is**
implemented and tested — supplying a corpus is the only remaining step. Neither
returns a fabricated score in the meantime. See
[docs/DETECTORS.md](docs/DETECTORS.md#dga) for the measured evidence behind that
decision.

## Measured performance

Real numbers from `uv run sih-ntd bench`, on
`Linux 7.1.6-arch1-1 x86_64, Python 3.12.13, 12 logical CPUs`, single process,
121 664 synthetic events (`mixed` scenario, seed 1337):

| Configuration | Events/sec | p50 | p95 | p99 |
|---|---|---|---|---|
| full persistence (events + 120k feature vectors + results) | **1 584** | 0.150 ms | 1.36 ms | 2.05 ms |
| detection only (`SIH_STORE__PERSIST_FEATURES=false`) | **1 955** | 0.155 ms | 1.33 ms | 2.04 ms |

Stage split at full persistence: feature engine 51.5 s, detector inference 0.49 s,
fusion 2.45 s of 76.8 s total — the feature engine dominates, not the detectors.
Re-measure on your own hardware; nothing here is extrapolated. See
[docs/BENCHMARKING.md](docs/BENCHMARKING.md).

## Quick start

```bash
uv sync                                        # Python 3.12 venv
redis-server &                                 

# 1. In-process demo: synthetic traffic straight through the pipeline
uv run sih-ntd synth --scenario mixed --count 3000

# 2. Distributed demo: publish to Redis, consume with a worker
uv run sih-ntd synth --scenario mixed --count 3000 --stream
uv run sih-ntd worker --idle-exit

# 3. Serve it
uv run sih-ntd api                             # http://127.0.0.1:8000/docs
curl -s localhost:8000/api/v1/alerts | jq '.alerts[0].evidence'

# 4. Run the analyst console in another terminal
cd frontend && npm ci && npm run dev            # http://127.0.0.1:3000
```

To run the full local stack instead, use `docker compose up --build` and open
`http://127.0.0.1:3000`.

Mutating management routes (`POST /feedback`, `/replay/start`, alert status, and
model lifecycle actions) are local-only by default. If binding the API beyond
loopback, set `SIH_API__ADMIN_TOKEN` and send it as `Authorization: Bearer ...` or
`X-API-Key`.

A real alert, as served:

```
DDOS  HIGH  confidence=0.95
"Flood toward 10.0.0.9: syn_rate_1s=1.97e+03, flows_per_sec_1s=3.53e+03,
 unique_src_ips_5s=254, src_ip_entropy_5s=7.99"
reason_codes: SYN_FLOOD_RATE, FLOW_RATE_EXCEEDED, DISTRIBUTED_SOURCES, BASELINE_COLD
```

`BASELINE_COLD` is in there because the host's baseline had not warmed yet. The
system says so instead of claiming the traffic was abnormal *for that host*.

## Tests

```bash
uv run pytest                    # 210 tests
uv run pytest -m "not redis"     # skip tests needing a live redis
```

Includes a false-positive budget test: 3 000 benign synthetic flows must produce
**zero** detections.

## Docs

- [ARCHITECTURE](docs/ARCHITECTURE.md) — components, data flow, why each choice
- [DETECTORS](docs/DETECTORS.md) — per-detector logic, thresholds, known limits
- [CONTINUOUS_LEARNING](docs/CONTINUOUS_LEARNING.md) — offline retraining, champion/challenger, governance
- [ALERT_SCHEMA](docs/ALERT_SCHEMA.md) — every field of every schema
- [SETUP](docs/SETUP.md) — install, Zeek, Docker, configuration
- [BENCHMARKING](docs/BENCHMARKING.md) — how to measure, what was measured
- [SECURITY_MODEL](docs/SECURITY_MODEL.md) — trust boundaries, passive guarantee, threats to the system itself

## License

Not yet chosen — add one before publishing.
