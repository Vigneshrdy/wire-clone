import type { GraphNode, TopologyGraph } from "./topology-data";

export function connectedEdges(graph: TopologyGraph, nodeId: string) { return graph.edges.filter((edge) => edge.source === nodeId || edge.target === nodeId); }
export function counterpartIds(graph: TopologyGraph, nodeId: string) { return [...new Set(connectedEdges(graph, nodeId).map((edge) => edge.source === nodeId ? edge.target : edge.source))]; }
export function graphTotals(graph: TopologyGraph) { return { bytes: graph.edges.reduce((sum, edge) => sum + edge.bytes, 0), flows: graph.edges.reduce((sum, edge) => sum + edge.flows, 0), alertedEdges: graph.edges.filter((edge) => edge.alertIds.length).length, internal: graph.nodes.filter((node) => node.kind === "internal").length, external: graph.nodes.filter((node) => node.kind === "external").length }; }
export function findNode(graph: TopologyGraph, id?: string): GraphNode | undefined { return id ? graph.nodes.find((node) => node.id === id) : undefined; }
