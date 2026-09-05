# Detectors

Every detector implements one contract (`sih_ntd/detectors/base.py`):

```
DetectorMetadata   name, detector_version, technique, threat_class, state,
                   state_reason, model_version, feature_schema_version
DetectorInput      features (FeatureVector), timestamp, context
DetectorResult     detector_name, detector_version, threat_class, technique,
                   score, confidence, confidence_basis, severity_hint,
                   supporting_features, reason_codes, model_version,
                   feature_schema_version, shadow, flow_ids, pcap_references
```

Results are immutable. Returning `None` is the normal case — a benign window
produces no record, so the store is not filled with millions of `BENIGN` rows.

**Rules, statistics and ML are all first-class.** `technique` is recorded on every
result (`RULE` / `STATISTICAL` / `SUPERVISED` / `HYBRID`) so an alert never
overstates how much "AI" was involved. Forcing a model onto DDoS or port-scan
detection would replace checkable arithmetic with an unexplainable number.

All thresholds live in `sih_ntd/config.py` (`ThresholdSettings`) and are
env-overridable. None are hardcoded in detector bodies.

---

## DDoS — `READY`, HYBRID

Entity: `DESTINATION`. Fires only when `flow_count_1s >= 20`, so a rate computed
from a nearly-empty window cannot trigger anything.

Triggers (strongest one sets the score):

| Reason code | Condition |
|---|---|
| `SYN_FLOOD_RATE` | `syn_rate_1s >= 500` and `syn_ratio_5s >= 0.5` |
| `UDP_FLOOD_RATE` | `udp_rate_1s >= 1000` and `udp_ratio_5s >= 0.5` |
| `FLOW_RATE_EXCEEDED` | `flows_per_sec_1s >= 1000` |
| `PACKET_RATE_EXCEEDED` | `packets_per_sec_1s >= 20000` |
| `AMPLIFICATION_RATIO` | `amplification_ratio_5s >= 5` and UDP-dominated |

Corroboration (raises confidence, never fires alone): `DISTRIBUTED_SOURCES`
(≥50 unique sources **and** ≥4 bits of source entropy), `BASELINE_EXCEEDED`
(observed ≥10× the host's EWMA baseline). When no baseline is warm the result
carries `BASELINE_COLD` and severity is capped below `CRITICAL` — without a
baseline the system cannot claim the traffic is abnormal *for this host*.

Confidence: `0.5 + 0.4 × normalise_exceedance(observed, threshold)` plus at most
0.10 for corroboration, capped at 0.99. `normalise_exceedance` is log-scaled so a
100× flood is distinguishable from a 4× one.

Measured on a synthetic 250-source SYN flood: `syn_rate_1s` 1 970/s,
`unique_src_ips_5s` 254, `src_ip_entropy_5s` 7.99 bits, severity `HIGH`.

## Recon / port scanning — `READY`, RULE

Entity: `HOST`, 60-second window, minimum 20 flows.

Needs a fan-out trigger — `VERTICAL_PORT_SCAN` (≥20 unique ports),
`HORIZONTAL_HOST_SCAN` (≥25 unique hosts), or `NETWORK_SWEEP` (both) — **and** a
failure signal (`failed_ratio_60s >= 0.8` or `syn_ratio_60s >= 0.8`). The failure
gate is what separates a scanner from a busy proxy or backup agent: without it,
any client with wide fan-out looks like a scan. Tested explicitly
(`test_recon_ignores_a_busy_client_whose_connections_succeed`).

No ML. Fan-out and failure are counted exactly; a model would add nothing but
opacity.

## C2 beaconing — `READY`, STATISTICAL

Entity: `PAIR`. Requires ≥6 intervals, mean interval in [5 s, 3600 s],
`interarrival_cv <= 0.25`, `periodicity_score >= 0.7`, and absolute jitter
≤30 s.

`periodicity_score = (1 - min(1, CV)) × min(1, n / min_intervals)` — regularity
scaled by how much evidence exists, so three lucky connections cannot score 1.0.

**Periodicity alone never fires.** At least two corroborating signals are
required from: `RARE_DESTINATION`, `STABLE_PAYLOAD_SIZE`,
`STABLE_CONNECTION_DURATION`, `EXTERNAL_DESTINATION`, `SHORT_CHECKIN_FLOWS`. NTP,
software updaters and monitoring agents are all excellent beacons; that is the
false positive this gate exists to prevent.

The 5-second interval floor was raised from 1 s after a fixture run produced a
false positive on ordinary ~1 s-interval uploads. Real implants sleep in tens of
seconds to minutes.

## DGA — `UNAVAILABLE`, SUPERVISED

The lexical feature extraction, dataset factory, trainer, evaluation, registry and
governance gates are all implemented and tested. There is **no champion model**,
so the detector reports `UNAVAILABLE` and returns nothing.

### Why, with the measurements

A model was trained on a lab corpus (5 synthetic DGA families + synthesised benign
names, stratified 70/15/15, one DGA family held out entirely). Results:

| Evaluation set | Precision | Recall | ROC-AUC |
|---|---|---|---|
| in-distribution test split | 1.000 | 1.000 | 1.000 |
| held-out `dictionary` family | 0.000 | 0.000 | 0.500 |
| hand-written out-of-corpus DGA probe (12 names) | — | **0.000** | — |

A perfect in-distribution score with zero transfer means the model learned *which
generator wrote this string*, not *is this string random*. Three successive corpus
redesigns (shared zone structure, shared random-label sampler, reduced model
capacity) did not fix it: a corpus built from generators is separable by
construction, and a model fitted to it does not generalise.

Two governance gates therefore block promotion, by design:

- `generalises_to_independent_generator` — under 50 % of out-of-corpus probe names
  detected
- `not_implausibly_perfect` — precision and recall both exactly 1.0

Shipping that model with `CALIBRATED_PROBABILITY` confidence would have been fake
AI with a fabricated metric attached. Instead the gap is visible in
`GET /api/v1/model-health`.

### To make it READY

1. Provide a real benign corpus (e.g. a Tranco snapshot) and real DGA samples
   (e.g. DGArchive) as CSV.
2. Extend `sih_ntd/ml/dataset.py` to load them instead of synthesising.
3. `uv run sih-ntd train-dga` → `sih-ntd models evaluate dga` → `promote`.
4. Restart workers.

The architecture allows a character-level neural model later: register any artefact
with `predict_proba` and the same feature contract. Nothing in `detectors/dga.py`
assumes a linear model.

For a lab demo only, `--acknowledge not_implausibly_perfect --reason "..."`
promotes despite a gate, and the override is recorded permanently in the promotion
history.

## DNS tunnelling — `READY`, HYBRID

Entity: `HOST`, per-query vectors that also carry the host's windowed DNS
behaviour, so one input has both halves of the evidence.

Requires a **lexical** trigger and a **behavioural** trigger:

- lexical: `OVERSIZED_QUERY_NAME` (≥60 chars), `HIGH_QUERY_ENTROPY` (≥3.6 bits/char
  with ≥24-char payload), `HEX_ENCODED_SUBDOMAIN`, `DEEP_ENCODED_SUBDOMAIN`
- behavioural: `UNIQUE_SUBDOMAIN_PER_QUERY` (≥80 % unique names over ≥20 queries),
  `EXCESSIVE_TXT_QUERIES`, `SUSTAINED_QUERY_RATE`, `RESPONSE_LARGER_THAN_QUERY`

Two thresholds were recalibrated after the mixed-traffic fixture produced a false
positive: the entropy trigger's minimum payload rose from 16 to 24 characters, and
`RESPONSE_LARGER_THAN_QUERY` now needs a ≥300-byte response as well as a ratio ≥6.
An ordinary A-record answer is already several times the query name's length, so
ratio alone flagged normal DNS.

## TLS/QUIC encrypted malware — `UNAVAILABLE`, SUPERVISED

**No decryption anywhere.** Only handshake metadata is available: JA4/JA4S, offered
ciphers, TLS version, SNI shape, certificate characteristics, session size/timing.
The feature engine produces these vectors (`FeatureEngine._tls_vector`).

Doing this honestly needs a labelled JA4/JA4S corpus or reviewed fingerprint
intelligence. Neither ships here. The alternative — scoring "rare JA4 +
self-signed certificate" as malware — produces a stream of false positives with an
invented confidence attached: corporate software, IoT firmware and any updated TLS
stack all produce fingerprints a given sensor has never seen. **A rare fingerprint
is a lead, not evidence.**

Register a champion named `tls_malware` and the detector starts scoring under the
same contract as DGA.

## Data exfiltration — `READY`, STATISTICAL

Entity: `HOST`, 300-second window. Only internal→external flows.

Volume is the trigger (`bytes_out_total_300s >= 10 MB`) but **never fires alone** —
at least one of `OUTBOUND_DOMINATED_TRANSFER` (out/in ratio ≥20),
`RARE_DESTINATION` (rarity ≥0.9), `BASELINE_DEVIATION` (z-score ≥4),
`ABOVE_HISTORICAL_P95` is required. Backups, CI uploads and video calls move large
amounts of data outbound every day.

Cold start is explicit: with no warm baseline the result carries `BASELINE_COLD`,
so nobody reads the alert as "abnormal for this host" when that has not been
established. Confidence weights baseline evidence highest
(0.35) over volume (0.25), ratio (0.25) and rarity (0.10).

---

## Confidence vs severity

Two different questions, computed separately:

- **confidence** — how strongly the evidence supports the classification.
  `confidence_basis` records how it was derived: `RULE_EVIDENCE`,
  `NORMALISED_ANOMALY`, `CALIBRATED_PROBABILITY`, or `FUSION`. Every value is
  reproducible from the stored `supporting_features`.
- **severity** — potential security impact. Starts from the detector's own
  assessment (it knows the volumes), applies a floor for classes that imply
  compromise (`C2_BEACON`, `EXFILTRATION`, `DNS_TUNNEL` ≥ `MEDIUM`), and escalates
  one step when ≥2 other detectors independently agree.

High confidence in a small event stays `LOW` severity. Asserted in
`tests/unit/test_fusion.py::test_severity_is_not_confidence`.

## Fusion

1. **Duplicate suppression** — a sustained flood produces one result per emit tick;
   the first becomes an alert, the rest bump `dedup_count` and `last_seen`.
2. **Cross-detector corroboration** —
   `confidence = min(0.99, primary + 0.08 × distinct_corroborating_detectors)`.
   Bounded, monotonic, recomputable from `evidence.detector_contributions`.
3. **Incident grouping** — two or more *distinct* threat classes on one subject
   within 300 s become an `Incident`. One class is an alert; two is a story.

Shadow (challenger) results are dropped by `ThreatFusion.ingest` and can never
become alerts.

## Adding a detector

1. Subclass `Detector`, set `name`/`version`/`threat_class`/`technique`/`entity_kinds`.
2. Read features via `FeatureVector.get`/`require`. Add new features to
   `features/engine.py` — never compute windows inside a detector.
3. Put thresholds in `ThresholdSettings`.
4. Return `self.build_result(...)` with `reason_codes` and `supporting_features`, or
   `None`.
5. Register it in `build_default_registry`.
6. Add detection tests: a positive case, a benign case, and a boundary case.
