# Security model

Two separate concerns:

1. **What the system is allowed to do** to the monitored network — nothing but
   observe.
2. **How the system defends itself** — because every input it consumes is chosen,
   at least in part, by hosts on the network it is watching.

---

## 1. The passive guarantee

The system operates inside a monitoring enclave with no route back into the
monitored production network. It therefore:

- **never transmits toward a monitored host.** No socket is opened to any captured
  address, anywhere in the codebase.
- **never probes, scans or completes a handshake.** It cannot query a source system.
- **never blocks, filters or mitigates.** There is no inline path and no
  device-control code.
- **never decrypts.** TLS/QUIC analysis uses handshake metadata only (JA4/JA4S, SNI,
  version, cipher, certificate attributes, size and timing envelopes).

Output is security intelligence only.

### How it is enforced

By absence, and by a test that asserts the absence
(`tests/security/test_untrusted_input.py::test_no_module_opens_a_socket_toward_captured_addresses`).
It parses the AST of every module that touches captured data — `baselines`,
`evidence`, `fusion`, `features/engine`, `features/stats` and all seven detectors —
and fails if any of them imports `socket`, `requests`, `urllib`, `httpx`,
`subprocess`, `http` or `ftplib`, or calls `eval`, `exec`, `system` or `popen`.

Network I/O exists in exactly three places, none of which handles captured content
as instructions:

| Module | I/O | Direction |
|---|---|---|
| `streaming.py` | Redis, inside the enclave | outbound to infrastructure |
| `api.py` | HTTP/WebSocket server | inbound from operators |
| `sensor/replay.py` | `subprocess` running Zeek on a local file | no network at all |

The `resp_*` fields on `NormalizedEvent` are optional precisely because on a truly
unidirectional tap the reverse direction may be invisible. Detectors are written not
to assume they are present.

---

## 2. Defending the system

### Captured traffic is untrusted input

A host on the monitored network chooses the domain names, SNI values, byte counts
and even which fields appear. `ingest.py` is the trust boundary:

- field names are looked up through a static alias table — never `eval`'d, never
  used for dynamic attribute access
- every value passes Pydantic validation with `extra="forbid"`; a failing record is
  **rejected and counted**, never coerced
- domains are validated (≤253 chars, ≤63-char labels, LDH charset plus `_` and `*`)
  and canonicalised
- IPs via `IPvAnyAddress`, ports bounded 0–65535, counters must be non-negative
- free-text fields are length-capped; list fields are count-capped
- rejection reasons are bucketed to a small fixed set before reaching metrics

Tested against oversized names, oversized labels, SQL-looking strings,
shell-looking strings, path-traversal-looking strings, markup, malformed IPs,
out-of-range ports, unparseable timestamps, negative byte counts and 500-element
answer lists.

### Metric cardinality

An IP address as a Prometheus label value is an unbounded time series and a way to
take down the scrape target. `metrics.py` accepts only label names declared at
construction; passing an undeclared label raises `ValueError`. An API test asserts
that no `203.0.113.*` address appears anywhere in `/metrics`.

### Resource exhaustion

A spoofed-source flood creates one entity per source address. `LruStateMap` bounds
the feature engine (default 50 000 entities) and the baseline store, evicting the
least-recently-seen and counting evictions. Window contents are bounded by time;
`IntervalTracker` by count.

### Model artifacts

`joblib.load` executes pickle opcodes. The registry only calls it on a file whose
SHA-256 matches the hash recorded when *this system* produced it, and then checks
the loaded object's class name against the recorded `estimator_class`. Anything else
raises `ArtifactIntegrityError`. Tested for tampering, absence and substitution.

Artefacts are treated as **locally produced**. Never point `SIH_REGISTRY__ROOT` at a
directory a third party can write to.

### Model poisoning

The full argument is in [CONTINUOUS_LEARNING.md](CONTINUOUS_LEARNING.md). In short:
live traffic can only ever become a *training candidate*, and reaching production
requires analyst labelling, dataset building, evaluation, governance gates and an
explicit human promotion. Training registers `CANDIDATE`. Drift emits signals and
calls nothing. Shadow inference is dropped by fusion. No code path writes to a
champion at runtime.

### Threat intelligence

External feeds are data, never instructions. Normalised, validated, provenance
recorded, `reviewed` flag carried. Cannot execute code, change configuration,
promote a model, or alter a detection rule without review.

### Secrets

Configuration comes from the environment. `.env` is gitignored; `.env.example` holds
placeholders only. No credentials are logged: `logging_conf.py` emits structured
JSON, and captured strings such as domains and SNI are logged at DEBUG only, so a
crafted name cannot forge a plausible INFO-level log line.

### Subprocess use

Exactly one: `sensor/replay.py` running Zeek. The PCAP path may come from an API
request, so it must resolve inside `SIH_SENSOR__PCAP_DIR`, have a `.pcap` or
`.pcapng` suffix, and point at a regular file before Zeek is invoked. Zeek argv is
a list and `shell=` is never passed. Asserted on the AST, not by grepping text.

### Management API access

Read-only routes remain unauthenticated for local demos. Mutating management routes
(`POST /feedback`, `POST /replay/start`, alert status updates, and model lifecycle
actions) are guarded by `require_management_access`:

- if `SIH_API__ADMIN_TOKEN` is configured, callers must supply it as
  `Authorization: Bearer <token>` or `X-API-Key`
- if no token is configured, these routes are allowed only while the API is bound
  to `127.0.0.1`, `::1`, or `localhost`
- binding to `0.0.0.0` without a token disables these routes with HTTP 503

---

## 3. Known gaps

Stated plainly rather than left for a reviewer to find.

| Gap | Impact | Mitigation today |
|---|---|---|
| Read-only API has no authentication | anyone who can reach the port can read alerts/flows | binds to `127.0.0.1` by default; put behind an authenticated reverse proxy before broad exposure |
| No role-based authorisation | a holder of the admin token can perform any management action | promotion is gated and fully audited, but not role-scoped |
| No TLS on the API or Redis | plaintext inside the enclave | run behind a reverse proxy; enable Redis TLS |
| No rate limiting | a client can exhaust the API | reverse proxy |
| SQLite, single writer | not suitable for multi-host scale-out | documented ClickHouse seam in `store.py` |
| Alerts contain IP addresses and domain names | these are personal data in some jurisdictions | no payload content is ever stored; apply retention (`sih-ntd store prune`) |
| Baselines are in-memory per worker | a restart loses warm baselines; cold start is then reported honestly | `BaselineStore.snapshot()`/`restore()` exist but are not yet wired to the store |
| No signing of model artifacts | integrity is verified by hash, authenticity is not | keep the registry on trusted local storage |

## 4. Reviewer checklist

- `uv run pytest tests/security/test_untrusted_input.py -k socket` → passes (AST check;
  a text grep also matches the prose in `detectors/base.py` that explains the rule)
- `grep -rn "shell=True\|eval(\|exec(" sih_ntd/` → no hits
- `grep -rn "pickle.load" sih_ntd/` → no hits (only `joblib.load` behind a hash check)
- `uv run pytest tests/security -q` → passes
- `curl -s localhost:8000/metrics | grep -c '203\.0\.113'` → 0
