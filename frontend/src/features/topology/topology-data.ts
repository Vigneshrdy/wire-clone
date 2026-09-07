import type { Alert, Flow } from "@/lib/api/schemas";
import { isPrivateAddress, logicalPosition, type Position } from "./layout";

export type GraphNode = { id: string; kind: "internal" | "external"; position: Position; connections: number; bytes: number; alerts: number; services: string[] };
export type GraphEdge = { id: string; source: string; target: string; bytes: number; flows: number; severity?: string; alertIds: string[] };
export type TopologyGraph = { nodes: GraphNode[]; edges: GraphEdge[]; totalNodes: number; totalEdges: number; truncated: boolean };

const severityRank = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

export function buildTopology(flows: Flow[], alerts: Alert[] = [], caps = { nodes: 200, edges: 500 }): TopologyGraph {
  const alertPairs = new Map<string, Alert[]>();
  alerts.forEach((alert) => { if (alert.src_ip && alert.dst_ip) { const key = `${alert.src_ip}>${alert.dst_ip}`; alertPairs.set(key, [...(alertPairs.get(key) ?? []), alert]); } });
  const edgeMap = new Map<string, GraphEdge>();
  const nodeStats = new Map<string, Omit<GraphNode, "position">>();
  flows.forEach((flow) => {
    const key = `${flow.src_ip}>${flow.dst_ip}`;
    const related = alertPairs.get(key) ?? [];
    const edge = edgeMap.get(key) ?? { id: key, source: flow.src_ip, target: flow.dst_ip, bytes: 0, flows: 0, alertIds: [] };
    edge.bytes += flow.orig_bytes + (flow.resp_bytes ?? 0); edge.flows += 1;
    edge.alertIds = [...new Set([...edge.alertIds, ...related.map((alert) => alert.alert_id)])];
    edge.severity = related.reduce<string | undefined>((highest, alert) => !highest || severityRank.indexOf(alert.severity) > severityRank.indexOf(highest) ? alert.severity : highest, edge.severity);
    edgeMap.set(key, edge);
    for (const id of [flow.src_ip, flow.dst_ip]) {
      const current = nodeStats.get(id) ?? { id, kind: isPrivateAddress(id) ? "internal" : "external", connections: 0, bytes: 0, alerts: 0, services: [] };
      current.connections += 1; current.bytes += flow.orig_bytes + (flow.resp_bytes ?? 0); current.alerts += related.length;
      if (flow.service && !current.services.includes(flow.service)) current.services.push(flow.service);
      nodeStats.set(id, current);
    }
  });
  const rankedEdges = [...edgeMap.values()].sort((a, b) => b.flows - a.flows).slice(0, caps.edges);
  const rankedNodes = [...nodeStats.values()].sort((a, b) => b.connections - a.connections).slice(0, caps.nodes);
  const internal = rankedNodes.filter((node) => node.kind === "internal");
  const external = rankedNodes.filter((node) => node.kind === "external");
  const nodes = [...internal.map((node, index) => ({ ...node, position: logicalPosition(node.id, true, index, internal.length) })), ...external.map((node, index) => ({ ...node, position: logicalPosition(node.id, false, index, external.length) }))];
  const ids = new Set(nodes.map((node) => node.id));
  return { nodes, edges: rankedEdges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)), totalNodes: nodeStats.size, totalEdges: edgeMap.size, truncated: nodeStats.size > caps.nodes || edgeMap.size > caps.edges };
}
