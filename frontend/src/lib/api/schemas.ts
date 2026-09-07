import { z } from "zod";

export const SeveritySchema = z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
export const AlertStatusSchema = z.enum(["NEW", "TRIAGED", "CONFIRMED", "DISMISSED", "SUPPRESSED"]);
export const ThreatClassSchema = z.enum(["BENIGN", "DDOS", "C2_BEACON", "DGA", "DNS_TUNNEL", "TLS_MALWARE", "RECON", "EXFILTRATION"]);
export const TechniqueSchema = z.enum(["RULE", "STATISTICAL", "SUPERVISED", "HYBRID"]);

export const EvidenceSchema = z.object({
  summary: z.string(),
  reason_codes: z.array(z.string()),
  observations: z.record(z.string(), z.number()),
  baseline_comparisons: z.record(z.string(), z.number()),
  detector_contributions: z.record(z.string(), z.number()),
  feature_importances: z.record(z.string(), z.number()),
  flow_ids: z.array(z.string()),
  pcap_references: z.array(z.string()),
});

export const AlertSchema = z.object({
  schema_version: z.string(), alert_id: z.string(), timestamp: z.string(), first_seen: z.string(), last_seen: z.string(),
  threat_class: ThreatClassSchema, confidence: z.number(), confidence_basis: z.string(), severity: SeveritySchema,
  status: AlertStatusSchema, src_ip: z.string().nullable(), dst_ip: z.string().nullable(), entity_kind: z.string(), entity_id: z.string(),
  detector_name: z.string(), detector_version: z.string(), technique: TechniqueSchema, model_version: z.string().nullable(),
  feature_schema_version: z.string(), correlation_id: z.string().nullable(), incident_id: z.string().nullable(), event_count: z.number(),
  dedup_count: z.number(), evidence: EvidenceSchema, lineage: z.object({ detector_versions: z.record(z.string(), z.string()), model_versions: z.record(z.string(), z.string()), feature_schema_version: z.string(), event_schema_version: z.string(), pipeline_run_id: z.string().nullable() }),
  contributing_detectors: z.array(z.string()),
});
export type Alert = z.infer<typeof AlertSchema>;

export const AlertsResponseSchema = z.object({ count: z.number(), total: z.number(), limit: z.number(), offset: z.number(), alerts: z.array(AlertSchema) });
export const AlertDetailSchema = z.object({ alert: AlertSchema, history: z.array(z.object({ timestamp: z.union([z.number(), z.string()]), kind: z.string(), detail: z.record(z.string(), z.unknown()) })) });

export const IncidentSchema = z.object({
  incident_id: z.string(), created_at: z.string(), updated_at: z.string(), first_seen: z.string(), last_seen: z.string(), entity_kind: z.string(), entity_id: z.string(), primary_threat_class: ThreatClassSchema, threat_classes: z.array(ThreatClassSchema), severity: SeveritySchema, confidence: z.number(), alert_ids: z.array(z.string()), alert_count: z.number(), summary: z.string(), status: AlertStatusSchema,
});
export type Incident = z.infer<typeof IncidentSchema>;

export const FlowSchema = z.looseObject({
  event_id: z.string(), ts: z.number(), ingest_ts: z.number(), sensor_id: z.string(), source_type: z.string(), flow_id: z.string(), src_ip: z.string(), src_port: z.number().nullable(), dst_ip: z.string(), dst_port: z.number().nullable(), transport: z.string(), service: z.string().nullable(), direction: z.string(), duration: z.number(), orig_packets: z.number(), resp_packets: z.number().nullable(), orig_bytes: z.number(), resp_bytes: z.number().nullable(), connection_state: z.string().nullable(), dns_query: z.string().nullable(), dns_qtype: z.string().nullable(), dns_rcode: z.string().nullable(), tls_ja4: z.string().nullable(), tls_sni: z.string().nullable(), tls_version: z.string().nullable(), pcap_reference: z.string().nullable(),
});
export type Flow = z.infer<typeof FlowSchema>;

export const DetectorSchema = z.object({ name: z.string(), detector_version: z.string(), technique: TechniqueSchema, threat_class: ThreatClassSchema, state: z.enum(["READY", "UNAVAILABLE", "DISABLED", "DEGRADED", "ERROR"]), state_reason: z.string().nullable(), model_version: z.string().nullable(), feature_schema_version: z.string() });
export type Detector = z.infer<typeof DetectorSchema>;

export const ModelSchema = z.object({ detector: z.string(), model_id: z.string(), model_version: z.string(), artifact_path: z.string(), artifact_hash: z.string(), estimator_class: z.string(), feature_schema_version: z.string(), feature_names: z.array(z.string()), dataset_id: z.string().nullable(), training_time: z.string(), training_duration_seconds: z.number(), metrics: z.record(z.string(), z.number()), status: z.enum(["CANDIDATE", "CHALLENGER", "CHAMPION", "RETIRED", "REJECTED"]), seed: z.number(), notes: z.string() });
export type Model = z.infer<typeof ModelSchema>;

export const DriftSchema = z.object({ drift_id: z.string(), timestamp: z.string(), detector: z.string(), model_version: z.string().nullable(), feature: z.string().nullable(), drift_type: z.string(), metric: z.string(), score: z.number(), threshold: z.number(), window: z.string(), reference_size: z.number(), current_size: z.number(), recommendation: z.string() });
export type DriftEvent = z.infer<typeof DriftSchema>;

export const ReadySchema = z.object({ status: z.enum(["ok", "degraded"]), redis: z.boolean(), store: z.object({ path: z.string(), counts: z.record(z.string(), z.number()) }), detectors: z.record(z.string(), z.string()), detectors_unavailable: z.record(z.string(), z.string()) });
export const HealthSchema = z.object({ status: z.string(), schema_versions: z.record(z.string(), z.string()) });
export const SummarySchema = z.object({ by_threat_class: z.record(z.string(), z.number()), by_severity: z.record(z.string(), z.number()) });
export const BenchmarkSchema = z.looseObject({ benchmark_id: z.string(), ts: z.number(), name: z.string(), events: z.number(), duration_seconds: z.number(), events_per_second: z.number(), latency_p50_ms: z.number().nullable(), latency_p95_ms: z.number().nullable(), latency_p99_ms: z.number().nullable(), latency_max_ms: z.number().nullable(), alerts_generated: z.number(), hardware: z.string(), dataset: z.string().nullable() });

export const WsMessageSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("connected"), stream: z.string() }),
  z.object({ type: z.literal("keepalive") }),
  z.object({ type: z.literal("alert"), alert: AlertSchema }),
]);
