# Schemas

Authoritative definitions live in `sih_ntd/schemas.py`. Three independently
versioned contracts:

| Constant | Current | Governs |
|---|---|---|
| `EVENT_SCHEMA_VERSION` | `1.0.0` | `NormalizedEvent` |
| `FEATURE_SCHEMA_VERSION` | `1.0.0` | `FeatureVector` shape and semantics |
| `ALERT_SCHEMA_VERSION` | `1.0.0` | `Alert` |

An unknown `schema_version` on an event or alert is a validation error, not a
best-effort parse. Bumping `FEATURE_SCHEMA_VERSION` invalidates every trained
model: the registry refuses to load one recorded against a different version.

Every model uses `extra="forbid"` — an unrecognised field is an error, never
silently dropped. `DetectorResult`, `Alert`, `Evidence`, `Lineage`, `Incident`,
`ModelMetadata`, `DriftEvent` and `PromotionRecord` are frozen.

---

## NormalizedEvent

One observed flow plus optional protocol metadata — what a passive sensor can
actually see on a mirrored or unidirectional link.

| Field | Type | Notes |
|---|---|---|
| `schema_version` | semver | must equal `EVENT_SCHEMA_VERSION` |
| `event_id` | str | deterministic from (timestamp, flow key, kind) → idempotent replay |
| `timestamp` | datetime UTC | accepts epoch seconds; always stored tz-aware |
| `ingest_timestamp` | datetime UTC | when this system saw it |
| `sensor_id` | ≤256 chars | provenance only, never grants trust |
| `source_type` | enum | `LIVE_TAP` `SPAN` `DIODE` `PCAP_REPLAY` `ZEEK_LOG` `NETFLOW` `IPFIX` `SFLOW` `SYNTHETIC` |
| `flow_id` | str | sensor-supplied, or derived: SHA-256 of the 5-tuple, direction-sensitive |
| `src_ip` / `dst_ip` | IPvAnyAddress | both must be the same IP version |
| `src_port` / `dst_port` | 0–65535, optional | |
| `ip_version` | 4 or 6 | corrected from the addresses |
| `transport_protocol` | enum | `tcp` `udp` `icmp` `other` |
| `service` | ≤256 chars, optional | |
| `direction` | enum | `INBOUND` `OUTBOUND` `INTERNAL` `EXTERNAL` `UNKNOWN` |
| `duration` | ≥0 float, optional | |
| `orig_packets` / `orig_bytes` | ≥0 int | |
| `resp_packets` / `resp_bytes` | ≥0 int, **optional** | optional on purpose: on a truly unidirectional tap the reverse direction may be invisible, and detectors must not assume it |
| `connection_state` | ≤256 chars | Zeek conn_state (`S0`, `SF`, `REJ`, …) |
| `tcp_flags` | ≤256 chars | Zeek history string |
| `dns` | `DnsMetadata`, optional | |
| `tls` | `TlsMetadata`, optional | |
| `pcap_reference` | ≤256 chars, optional | filename only — captures are never copied into tables |
| `raw_event_reference` | ≤256 chars, optional | |

Derived properties: `epoch`, `total_bytes`, `total_packets`, `is_syn_only`
(TCP-only, never true for UDP), `failed`.

### DnsMetadata

`query` (validated: ≤253 chars, ≤63-char labels, LDH charset plus `_` and `*`,
lowercased, trailing dot stripped), `qtype`, `rcode`, `answers` (≤64, each ≤256
chars), `response_bytes`, `rejected`. Derived: `query_length`, `labels`,
`subdomain_depth`, `answer_count`. **No payload content, ever.**

### TlsMetadata

`version`, `sni` (validated as a domain), `ja4`, `ja4s`, `cipher`,
`cert_subject_cn`, `cert_issuer_cn`, `cert_validity_days`, `cert_self_signed`,
`established`. Metadata only — there is no decryption anywhere in the system.

---

## FeatureVector

| Field | Notes |
|---|---|
| `schema_version` | must equal `FEATURE_SCHEMA_VERSION` |
| `timestamp` | UTC |
| `entity_kind` | `HOST` `SUBNET` `DESTINATION` `SERVICE` `PROTOCOL` `PAIR` |
| `entity_id` | the source IP, destination IP or `src->dst` pair |
| `window_seconds` | widest window covered; `0.0` marks a per-event protocol vector |
| `values` | `{name: float}`, all finite (NaN/inf rejected) |
| `labels` | `{name: str}` — attacker-controlled context (queried domain, JA4, SNI), kept out of `values` so the numeric vector stays a clean model input |
| `event_count`, `flow_ids` (≤64), `pcap_references` (≤8) | provenance for evidence and PCAP pivoting |

`get(name, default)` for optional reads; `require(*names)` raises `KeyError` rather
than substituting `0.0`, because a silently zero-filled feature turns a broken
engine into "no alerts".

Windowed names carry an explicit suffix per window: `flows_per_sec_1s`,
`syn_rate_5s`, `unique_dst_ports_60s`, `bytes_out_total_300s`, and so on.
`windowed_feature_names()` enumerates all 238 of them for the current window
configuration. Groups: flow rates, source behaviour, entropy, timing, DNS
lexical/behavioural, TLS, exfiltration, baseline comparisons
(`*_zscore`, `*_baseline_mean`, `*_baseline_p95`, `*_baseline_warm`), and
`coverage_<window>`.

`*_baseline_warm` is emitted explicitly so a detector can tell "within baseline"
from "no baseline yet". A cold baseline yields z-score `0.0`, never a large number.

---

## DetectorResult

`detector_name`, `detector_version`, `threat_class`, `technique`, `score` (native
scale), `confidence` (0–1), `confidence_basis`, `severity_hint`, `timestamp`,
`entity_kind`, `entity_id`, `window_seconds`, `src_ip`, `dst_ip`,
`supporting_features`, `reason_codes` (≤32), `model_version`,
`feature_schema_version`, `shadow`, `flow_ids`, `pcap_references`.

`shadow=True` marks challenger output: persisted for comparison, dropped by fusion,
never an alert.

---

## Alert

| Field | Notes |
|---|---|
| `alert_id`, `schema_version` | |
| `timestamp`, `first_seen`, `last_seen` | `last_seen` advances as duplicates are suppressed |
| `threat_class` | `DDOS` `C2_BEACON` `DGA` `DNS_TUNNEL` `TLS_MALWARE` `RECON` `EXFILTRATION` |
| `confidence`, `confidence_basis` | `RULE_EVIDENCE` / `NORMALISED_ANOMALY` / `CALIBRATED_PROBABILITY` / `FUSION` |
| `severity` | `INFO` `LOW` `MEDIUM` `HIGH` `CRITICAL` — impact, computed separately from confidence |
| `status` | `NEW` `TRIAGED` `CONFIRMED` `DISMISSED` `SUPPRESSED` |
| `src_ip`, `dst_ip`, `entity_kind`, `entity_id` | |
| `detector_name`, `detector_version`, `technique`, `model_version`, `feature_schema_version` | |
| `correlation_id` | the subject: target for a flood, source otherwise |
| `incident_id` | set when ≥2 distinct threat classes correlate on one subject |
| `event_count`, `dedup_count` | |
| `evidence` | `Evidence` |
| `lineage` | `Lineage` |
| `contributing_detectors` | corroborating detector names |

No payload content is present in any field.

### Evidence

`summary` (one human-readable line), `reason_codes`, `observations` (what was seen),
`baseline_comparisons` (what it was compared against — thresholds, baselines,
z-scores, p95s), `detector_contributions` (`{detector: confidence}`),
`feature_importances` (reserved for asynchronous SHAP-style explanation),
`flow_ids` (≤128), `pcap_references` (≤16).

Observations and comparisons are split so a reader can tell measurement from
reference without knowing the feature naming convention.

Example:

```json
{
  "summary": "Flood toward 10.0.0.9: syn_rate_1s=1.97e+03, flows_per_sec_1s=3.53e+03, unique_src_ips_5s=254, src_ip_entropy_5s=7.99",
  "reason_codes": ["SYN_FLOOD_RATE","FLOW_RATE_EXCEEDED","DISTRIBUTED_SOURCES","BASELINE_COLD"],
  "observations": {"syn_rate_1s": 1970.0, "unique_src_ips_5s": 254.0, "src_ip_entropy_5s": 7.99},
  "baseline_comparisons": {"triggered_threshold": 500.0, "flows_per_sec_60s_baseline_mean": 0.0},
  "detector_contributions": {"ddos": 0.95}
}
```

### Lineage

`detector_versions`, `model_versions`, `feature_schema_version`,
`event_schema_version`, `pipeline_run_id`. Enough to reproduce the decision.

---

## Incident

`incident_id`, `created_at`, `updated_at`, `first_seen`, `last_seen`,
`entity_kind`, `entity_id`, `primary_threat_class`, `threat_classes`, `severity`,
`confidence`, `alert_ids` (≤512), `alert_count`, `summary`, `status`.

## AnalystFeedback

`feedback_id`, `alert_id`, `label` (`TRUE_POSITIVE` / `FALSE_POSITIVE` /
`FALSE_NEGATIVE` / `UNCERTAIN`), `corrected_threat_class` (**required** when the
label is `FALSE_NEGATIVE`), `analyst_id`, `analyst_confidence`, `notes` (≤4096),
`timestamp`.

## DriftEvent

`drift_id`, `timestamp`, `detector`, `model_version`, `feature`, `drift_type`
(`FEATURE_DISTRIBUTION` / `PREDICTION_DISTRIBUTION` / `CONFIDENCE_DISTRIBUTION` /
`CLASS_DISTRIBUTION` / `LABEL_PERFORMANCE`), `metric` (`psi` / `ks` /
`jensen_shannon` / `precision_drop`), `score`, `threshold`, `window`,
`reference_size`, `current_size`, `recommendation`. Derived: `breached`.

Carries no action field, by design.

## ModelMetadata / PromotionRecord / DatasetMetadata / BenchmarkResult

- **ModelMetadata** — `detector`, `model_id`, `model_version`, `artifact_path`,
  `artifact_hash` (SHA-256), `estimator_class`, `feature_schema_version`,
  `feature_names`, `dataset_id`, `training_time`, `training_duration_seconds`,
  `metrics`, `status`, `seed`, `notes`.
- **PromotionRecord** — `record_id`, `timestamp`, `detector`, `model_version`,
  `from_status`, `to_status`, `actor`, `reason`, `gate_results`,
  `previous_champion`.
- **DatasetMetadata** — `dataset_id`, `created_at`, `feature_schema_version`,
  `detector`, `source_summary`, `class_distribution`, `split_strategy`,
  `split_sizes`, `feature_names`, `label_provenance`, `content_hash`, `row_count`,
  `seed`.
- **BenchmarkResult** — `benchmark_id`, `timestamp`, `name`, `events`,
  `duration_seconds`, `events_per_second`, `latency_p50/p95/p99/max_ms`,
  `stage_seconds`, `alerts_generated`, `hardware`, `configuration`,
  `model_versions`, `dataset`. Fields are absent rather than estimated when a
  stage did not run.

## ThreatIntelIndicator

`indicator_id`, `kind` (`domain` / `ip` / `ja4` / `ja4s` / `sha256`), `value`
(validated per kind), `source`, `first_seen`, `confidence`, `tags`, `ingested_at`,
`reviewed`. Data only.
