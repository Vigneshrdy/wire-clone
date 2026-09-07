import { describe, expect, it } from "vitest";
import type { Alert, Flow } from "@/lib/api/schemas";
import { graphTotals } from "./graph-model";
import { isPrivateAddress, logicalPosition } from "./layout";
import { buildTopology } from "./topology-data";

const flow = (overrides: Partial<Flow> = {}): Flow => ({ event_id: "event", ts: 1, ingest_ts: 1, sensor_id: "sensor", source_type: "synthetic", flow_id: "flow", src_ip: "10.0.0.1", src_port: 1234, dst_ip: "8.8.8.8", dst_port: 53, transport: "udp", service: "dns", direction: "outbound", duration: 0.2, orig_packets: 1, resp_packets: 1, orig_bytes: 40, resp_bytes: 60, connection_state: "SF", dns_query: null, dns_qtype: null, dns_rcode: null, tls_ja4: null, tls_sni: null, tls_version: null, pcap_reference: null, ...overrides });
const alert = { alert_id: "alert-1", src_ip: "10.0.0.1", dst_ip: "8.8.8.8", severity: "HIGH" } as Alert;

describe("topology transforms", () => {
  it("classifies RFC1918 address ranges", () => { expect(isPrivateAddress("10.1.2.3")).toBe(true); expect(isPrivateAddress("172.31.1.2")).toBe(true); expect(isPrivateAddress("172.32.1.2")).toBe(false); expect(isPrivateAddress("192.168.1.2")).toBe(true); });
  it("produces stable lane positions", () => { expect(logicalPosition("10.0.0.1", true, 0, 1)).toEqual(logicalPosition("10.0.0.1", true, 0, 1)); expect(logicalPosition("10.0.0.1", true, 0, 1)[0]).toBeLessThan(0); expect(logicalPosition("8.8.8.8", false, 0, 1)[0]).toBeGreaterThan(0); });
  it("aggregates directional flows and correlates alerts", () => { const graph = buildTopology([flow(), flow({ flow_id: "flow-2", orig_bytes: 100 })], [alert]); expect(graph.nodes).toHaveLength(2); expect(graph.edges).toHaveLength(1); expect(graph.edges[0]).toMatchObject({ flows: 2, bytes: 260, severity: "HIGH", alertIds: ["alert-1"] }); expect(graphTotals(graph)).toMatchObject({ flows: 2, bytes: 260, alertedEdges: 1, internal: 1, external: 1 }); });
  it("marks capped graphs as truncated and removes orphaned edges", () => { const graph = buildTopology([flow(), flow({ flow_id: "flow-2", src_ip: "10.0.0.2", dst_ip: "1.1.1.1" })], [], { nodes: 2, edges: 1 }); expect(graph.truncated).toBe(true); expect(graph.nodes.length).toBeLessThanOrEqual(2); expect(graph.edges.length).toBeLessThanOrEqual(1); });
});
