import { describe, expect, it } from "vitest";
import { metricTotal, parseMetrics } from "./metrics";

describe("Prometheus parser", () => {
  it("parses labelled counters and totals a metric", () => { const samples = parseMetrics('# HELP ignored\nsih_alerts_total{severity="HIGH"} 3\nsih_alerts_total{severity="LOW"} 2\nsih_latency 1.25e+2\n'); expect(samples).toHaveLength(3); expect(samples[0].labels).toEqual({ severity: "HIGH" }); expect(metricTotal(samples, "sih_alerts_total")).toBe(5); expect(metricTotal(samples, "sih_latency")).toBe(125); });
  it("ignores malformed exposition lines", () => { expect(parseMetrics("not a metric\n# comment\n")).toEqual([]); });
});
