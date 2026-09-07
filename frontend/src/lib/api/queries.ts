import { z } from "zod";
import { apiGet, queryString } from "./client";
import { AlertDetailSchema, AlertSchema, AlertsResponseSchema, BenchmarkSchema, DetectorSchema, DriftSchema, FlowSchema, HealthSchema, IncidentSchema, ModelSchema, ReadySchema, SummarySchema } from "./schemas";

export const queries = {
  health: () => apiGet("health", HealthSchema),
  ready: () => apiGet("ready", ReadySchema),
  summary: () => apiGet("alerts/summary", SummarySchema),
  alerts: (params: Record<string, string | number | undefined> = {}) => apiGet(`alerts${queryString({ limit: 200, ...params })}`, AlertsResponseSchema),
  alert: (id: string) => apiGet(`alerts/${encodeURIComponent(id)}`, AlertDetailSchema),
  incidents: () => apiGet("incidents?limit=200", z.object({ count: z.number(), incidents: z.array(IncidentSchema) })),
  incident: (id: string) => apiGet(`incidents/${encodeURIComponent(id)}`, z.object({ incident: IncidentSchema, alerts: z.array(AlertSchema) })),
  flows: (params: Record<string, string | number | undefined> = {}) => apiGet(`flows${queryString({ limit: 500, ...params })}`, z.object({ count: z.number(), flows: z.array(FlowSchema) })),
  detectors: () => apiGet("detectors", z.object({ detectors: z.array(DetectorSchema) })),
  modelHealth: () => apiGet("model-health", z.object({ detectors: z.array(z.object({ detector: z.string(), state: z.string(), state_reason: z.string().nullable(), technique: z.string(), running_model_version: z.string().nullable(), champion_model_version: z.string().nullable(), champion_metrics: z.record(z.string(), z.number()), feature_schema_version: z.string() })) })),
  models: () => apiGet("models", z.object({ feature_schema_version: z.string(), registry: z.record(z.string(), z.object({ champion: ModelSchema.nullable(), challenger: ModelSchema.nullable(), model_count: z.number() })) })),
  detectorModels: (detector: string) => apiGet(`models/${encodeURIComponent(detector)}`, z.object({ detector: z.string(), models: z.array(ModelSchema), promotion_history: z.array(z.record(z.string(), z.unknown())) })),
  drift: () => apiGet("drift?limit=200", z.object({ count: z.number(), note: z.string(), events: z.array(DriftSchema) })),
  feedback: () => apiGet("feedback?limit=200", z.object({ count: z.number(), feedback: z.array(z.record(z.string(), z.unknown())) })),
  benchmarks: () => apiGet("benchmarks?limit=100", z.object({ count: z.number(), hardware_note: z.string(), results: z.array(BenchmarkSchema) })),
  replay: () => apiGet("replay/status", z.record(z.string(), z.unknown())),
};
