# Security Audit

## Scope

Defensive audit of the existing SIH 26145 implementation, focused on passive-only operation, command/path safety, model artifact safety, continuous-learning poisoning controls, management API exposure, streaming correctness, state bounds, and regression coverage.

## Architecture Reviewed

Reviewed `sih_ntd/` backend modules, detector mesh, Redis stream client, replay path, SQLite store seam, model registry/governance/dataset code, FastAPI routes, tests, docs, `.env.example`, and benchmark harness. Frontend UI design/build work was not expanded.

## Verification Method

- Read `.ai-project-state.md` before edits and verified claims against code.
- Captured git state before modifying files.
- Ran baseline suite before fixes: `uv run pytest` -> 192 passed, 2 warnings.
- Searched for fake implementations, outbound/network-capable code, shell execution, model loading, SQL, and management routes.
- Added regression tests for verified issues.
- Ran final suite: `uv run pytest` -> 210 passed, 2 warnings.
- Ran compile check: `uv run python -m compileall sih_ntd tests benchmarks` -> passed.
- Ran benchmark: `uv run sih-ntd bench --scenario mixed --count 2000` -> 1,576 events/sec on 12,164 generated events with full persistence.
- Attempted dependency audit: `uv run pip-audit` unavailable on this host.

## Findings Summary

Critical: 0 found, 0 fixed
High: 3 found, 3 fixed
Medium: 2 found, 2 fixed
Low: 2 found, 2 fixed

## Fixed Findings

### AUD-001

Severity: HIGH

Component: Replay / PCAP processing

Problem: `replay_pcap` accepted arbitrary filesystem paths. If Zeek is installed, an API caller could cause the service to read any local file path reachable by the process.

Impact: Path traversal / arbitrary local file processing via a management API.

Root Cause: `Path(pcap_path)` was passed to Zeek after only `is_file()` validation.

Fix: Added `validate_pcap_path`; relative and absolute paths must resolve under `SIH_SENSOR__PCAP_DIR`, use `.pcap`/`.pcapng`, and point to a file before Zeek runs.

Verification: `tests/security/test_untrusted_input.py::test_pcap_replay_rejects_paths_outside_configured_capture_dir` and accept-only configured capture test pass.

### AUD-002

Severity: HIGH

Component: API management routes

Problem: Mutating management routes were unauthenticated and depended only on default loopback binding.

Impact: If misbound to `0.0.0.0`, any reachable caller could start replay, submit poisoning feedback, change alert status, or invoke model lifecycle actions.

Root Cause: No access dependency on mutating FastAPI routes.

Fix: Added `SIH_API__ADMIN_TOKEN` and `require_management_access`. When token is configured it is required; when unset, management writes are disabled off-loopback.

Verification: `test_management_routes_are_disabled_without_token_when_bound_off_loopback` and `test_management_routes_require_configured_token` pass.

### AUD-003

Severity: HIGH

Component: Model registry

Problem: Detector names, model versions, dataset IDs, and metadata `artifact_path` were not constrained as safe registry path components.

Impact: Direct misuse or malicious metadata could escape the registry root or load the wrong trusted artifact.

Root Cause: Filesystem paths were composed from unvalidated strings and metadata-controlled relative paths.

Fix: Added registry component validation and artifact root/expected-path checks before `joblib.load`; dataset saves validate dataset IDs.

Verification: Registry traversal, escaped artifact, and mismatched artifact-path tests pass.

### AUD-004

Severity: MEDIUM

Component: Threat fusion / streaming idempotency

Problem: Alert IDs were random. Redis redelivery after a worker crash after persist but before ACK could create duplicate alert rows after restart.

Impact: Duplicate incidents/alerts under at-least-once delivery.

Root Cause: Idempotency existed for events, but not for derived alerts across process restarts.

Fix: Alert IDs are deterministic per detector, threat class, entity, and dedup time bucket. Store inserts duplicate alerts with `INSERT OR IGNORE`, preserving analyst status and audit history.

Verification: `test_duplicate_delivery_after_worker_restart_does_not_duplicate_alerts` passes.

### AUD-005

Severity: MEDIUM

Component: Threat fusion state

Problem: Fusion dedup/subject maps were only expired by explicit caller action, but the pipeline never called `expire()`.

Impact: Long-running workers could retain stale fusion state; high-cardinality alerts could grow memory until process pressure.

Root Cause: Expiry API existed but was not wired into event processing; maps were plain dicts.

Fix: Pipeline expires fusion state on event time and flush time; fusion maps use the existing `LruStateMap` capacity.

Verification: Fusion expiry and high-cardinality LRU tests pass.

### AUD-006

Severity: LOW

Component: Incident grouping

Problem: Incident idle reset logic compared after `last_seen` was already updated, so stale incidents could be reused after idle gaps.

Impact: Incorrect incident continuity after long quiet periods.

Root Cause: Ordering bug in `_fuse_one` / `_update_incident`.

Fix: Reset subject incident state before updating `last_seen` when the idle gap is exceeded.

Verification: `test_fusion_resets_incident_group_after_idle_gap` passes.

### AUD-007

Severity: LOW

Component: Documentation

Problem: README and API module docstring still claimed no frontend and no API auth, conflicting with current code and security posture.

Impact: Operator confusion and unsafe deployment assumptions.

Root Cause: Docs drift after implementation changes.

Fix: Updated README, API docstring, `.env.example`, and security model.

Verification: Docs reviewed against current code diff.

## Remaining Findings

- Read-only API routes are still unauthenticated. Keep loopback-only or deploy behind an authenticated reverse proxy.
- No role-based authorization; `SIH_API__ADMIN_TOKEN` is all-or-nothing for management actions.
- Zeek is not installed on this host, so real PCAP-to-Zeek execution remains unverified here. Path and subprocess safety are tested without executing Zeek.
- Dependency vulnerability scanning could not run because `pip-audit` is not installed.
- Baseline snapshot/restore exists but is not persisted across worker restarts.

## ML Validation Findings

DGA and TLS/QUIC malware detectors remain honestly unavailable without real labelled corpora. Registry hash/schema checks and promotion gates are enforced. Training registers candidates only; promotion remains explicit. Synthetic DGA metrics remain documented as lab-only and blocked by transfer/perfection gates.

## Streaming Findings

Redis Streams are at-least-once. Duplicate normalized events are idempotent by deterministic event IDs; this audit added deterministic alert IDs to extend idempotency across worker restarts. Redis NOGROUP recovery was already present in the dirty worktree and is regression tested.

## Continuous Learning Findings

No automatic path from live traffic or drift to model promotion was found. Feedback is stored as training-candidate data and requires alert references. Drift emits `DriftEvent` signals only.

## Performance Results

Command: `uv run sih-ntd bench --scenario mixed --count 2000`

Hardware: Linux 7.1.6 arch x86_64, Python 3.12.13, 12 logical CPUs

Generated events: 12,164

Throughput: 1,576 events/sec

Latency: p50 0.142 ms, p95 1.290 ms, p99 1.878 ms, max 152.744 ms

Stage time: feature engine 5.314 s, detector inference 0.054 s, fusion 0.117 s

Alerts: 7

## Known Limitations

- SQLite remains a prototype analytical store seam, not a ClickHouse deployment.
- Real throughput on Zeek logs, Redis round-trip throughput, multi-worker scaling, CPU/RAM ceilings, and Mbps are not measured in this audit.
- No TLS termination for API/Redis is configured by the app.
- No signed model artifacts; hash verifies integrity, not authenticity.

## Final Security Posture

The implementation still honors the passive/read-only monitored-network constraint in audited code paths. The highest-risk verified gaps found in this pass were fixed and regression tested. Remaining issues are deployment hardening, external dependency/tooling gaps, real-corpus ML validation, Zeek-host verification, and baseline persistence.
