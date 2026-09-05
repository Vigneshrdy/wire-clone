# Setup

## Requirements

| Component | Requirement | Notes |
|---|---|---|
| Python | 3.12 (`>=3.12,<3.14`) | 3.12 has the widest wheel coverage for numpy/scikit-learn; the repo pins it via `.python-version` |
| uv | any recent version | manages the venv and the lockfile |
| redis-server | 7.x | required for the streaming worker and `/ws/alerts`; **not** required to serve stored alerts |
| Zeek | optional, host install | only for the PCAP path — see below |
| Docker | optional | `docker compose` stack for redis + api + worker |

No internet access is needed at runtime.

## Install

```bash
git clone <this repo> && cd sih-kmit
uv sync                     # creates .venv, installs deps + this package
cp .env.example .env         # optional; defaults work as-is
```

Verify:

```bash
uv run pytest -m "not redis" -q       # runs without a redis server
uv run sih-ntd store health
```

## Run

### Everything in one process (no Redis needed)

```bash
uv run sih-ntd synth --scenario mixed --count 3000
```

Generates seeded metadata and runs it straight through features → detectors →
fusion → alerts → store. Prints a summary.

Scenarios: `benign`, `ddos_syn`, `ddos_udp_amp`, `scan_vertical`,
`scan_horizontal`, `c2_beacon`, `dga`, `dns_tunnel`, `exfil`, `mixed`.

### Distributed (Redis + worker + API)

```bash
redis-server &                                     # or docker compose up -d redis

uv run sih-ntd synth --scenario mixed --count 3000 --stream   # publish
uv run sih-ntd worker --consumer worker-1                     # consume (Ctrl-C to stop)
uv run sih-ntd api                                            # serve
```

Add `--idle-exit` to the worker to stop once the stream is drained (used by tests).
Run several workers with different `--consumer` names: the consumer group
distributes entries between them.

### API

```
http://127.0.0.1:8000/docs          OpenAPI UI
GET  /health  /ready  /metrics
GET  /api/v1/alerts?threat_class=DDOS&min_confidence=0.9&limit=50
GET  /api/v1/alerts/{id}            alert + append-only decision history
POST /api/v1/alerts/{id}/status
GET  /api/v1/alerts/summary
GET  /api/v1/incidents  /api/v1/incidents/{id}
GET  /api/v1/flows
GET  /api/v1/detectors              includes UNAVAILABLE states + reasons
GET  /api/v1/models  /api/v1/models/{detector}  /api/v1/model-health
POST /api/v1/models/{detector}/evaluate | promote | rollback
GET  /api/v1/drift
POST /api/v1/feedback               GET /api/v1/feedback
GET  /api/v1/benchmarks
POST /api/v1/replay/start           GET /api/v1/replay/status
WS   /ws/alerts                     live feed, tails network.alerts
```

The prototype binds to `127.0.0.1` and has **no authentication**. Read
[SECURITY_MODEL.md](SECURITY_MODEL.md) before changing that: the mutating routes
can promote a model and start a replay job.

## Zeek (PCAP path)

Zeek is a **host dependency** and is deliberately not bundled — it is large and only
the PCAP path needs it.

```bash
# Arch
sudo pacman -S zeek
# Debian/Ubuntu: see https://docs.zeek.org/en/master/install.html
zeek --version

uv run sih-ntd replay /path/to/capture.pcap
uv run sih-ntd replay /path/to/capture.pcap --stream       # via Redis
```

The pipeline runs `zeek -r <pcap> LogAscii::use_json=T` in a temp directory, reads
`conn.log` / `dns.log` / `ssl.log`, correlates them by `uid`, and tags every event
with the capture filename for evidence.

Without Zeek installed, `sih-ntd replay` fails with a clear message and exit code 2.
It does **not** silently substitute synthetic data for a capture you asked to
analyse. `ZeekLogReader` itself is unit-tested against fixture JSON, so the ingest
path is verified even where Zeek is absent.

For JA4/JA4S, install the Zeek JA4 plugin; the fields are read automatically when
present (`ja4`, `ja4s`).

### Other sources

`sih_ntd/ingest.py` maps NetFlow/IPFIX-style records through the same alias table
(`sourceIPv4Address`, `octetDeltaCount`, `flowDurationMilliseconds`, IANA protocol
numbers, …). Adding a source means adding aliases, not a new code path.

## Docker

```bash
docker compose up -d              # redis + api + worker-detection
docker compose logs -f worker-detection
curl -s localhost:8000/health
```

The API and worker share one SQLite file in WAL mode (worker writes, API reads).
There is no ClickHouse container: the prototype's store is SQLite — see
[ARCHITECTURE.md](ARCHITECTURE.md#storage-sqlite-now-clickhouse-later).

## Configuration

Everything is env-overridable with the `SIH_` prefix and `__` nesting:

```bash
SIH_THRESHOLDS__DDOS_SYN_RATE=2000 uv run sih-ntd synth --scenario ddos_syn --count 5000
SIH_STORE__PERSIST_FEATURES=false uv run sih-ntd bench --count 50000
SIH_WINDOWS__SIZES='[1.0,10.0,60.0]' uv run sih-ntd api
```

Groups: `redis`, `store`, `sensor`, `windows`, `thresholds`, `fusion`, `registry`,
`drift`, `api`, `logging`, `replay`. Full list with defaults and comments in
`sih_ntd/config.py`; annotated copy in `.env.example`.

Two settings worth knowing:

- `SIH_SENSOR__HOME_NETWORKS` — CIDRs treated as "inside". The exfiltration detector
  and direction tagging depend on this being right for your environment.
- `SIH_STORE__PERSIST_FEATURES` — `false` gives ~25 % more throughput but removes the
  feature history that the drift engine and training factory read.

## Maintenance

```bash
uv run sih-ntd store health
uv run sih-ntd store prune --days 30    # drops events/features/results; keeps alerts
uv run sih-ntd bench --scenario mixed --count 20000
uv run sih-ntd train-dga
uv run sih-ntd models list
uv run sih-ntd drift --detector dga
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `StreamUnavailable: redis not reachable` | redis-server is not running; `redis-cli ping` should return `PONG` |
| `/ready` reports `degraded` | Redis is down. Stored alerts still serve; the worker cannot run |
| `dga` / `tls_malware` show `UNAVAILABLE` | expected — no champion model. See [DETECTORS.md](DETECTORS.md#dga) |
| No alerts from a short replay | fixed: the worker flushes open windows when the stream goes quiet. If you call `Pipeline.handle_events` directly, leave `flush=True` |
| `error: 'zeek' not found on PATH` | install Zeek, or use `sih-ntd synth` |
| Promotion returns HTTP 409 | a governance gate blocked it; the response body names which |
| `SchemaVersionMismatch` on model load | `FEATURE_SCHEMA_VERSION` changed — retrain |
