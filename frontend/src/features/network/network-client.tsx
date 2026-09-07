"use client";

import { useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import { useMemo, useState } from "react";
import { StatusBadge } from "@/components/ui/status-badge";
import { queries } from "@/lib/api/queries";
import { bytes, label, number } from "@/lib/format";
import { connectedEdges, counterpartIds, findNode, graphTotals } from "@/features/topology/graph-model";
import { buildTopology } from "@/features/topology/topology-data";
import { FlowTable } from "./flow-table";

const TopologyCanvas = dynamic(() => import("@/features/topology/topology-canvas").then((module) => module.TopologyCanvas), { ssr: false, loading: () => <div className="topology-loading">Loading analytical topology</div> });

export function NetworkClient() {
  const flows = useQuery({ queryKey: ["flows"], queryFn: () => queries.flows(), refetchInterval: 30_000 });
  const alerts = useQuery({ queryKey: ["alerts", "network"], queryFn: () => queries.alerts({ limit: 200 }), refetchInterval: 20_000 });
  const [selected, setSelected] = useState<string>();
  const graph = useMemo(() => buildTopology(flows.data?.flows ?? [], alerts.data?.alerts ?? []), [flows.data, alerts.data]);
  const totals = graphTotals(graph);
  const node = findNode(graph, selected);
  const edges = node ? connectedEdges(graph, node.id) : [];
  return <div><header className="page-heading"><div><h2>Network relationships</h2><p>Deterministic logical topology from stored flow metadata. Positions do not represent geography.</p></div>{graph.truncated ? <StatusBadge value="DEGRADED" /> : <StatusBadge value="READY" />}</header><section className="network-strip"><span><b>{number(totals.internal, 0)}</b> internal hosts</span><span><b>{number(totals.external, 0)}</b> destinations</span><span><b>{number(totals.flows, 0)}</b> observed flows</span><span><b>{bytes(totals.bytes)}</b> transferred</span><span><b>{number(totals.alertedEdges, 0)}</b> alerted links</span><button onClick={() => setSelected(undefined)}>Reset focus</button></section><section className="network-workspace"><div className="topology-stage"><TopologyCanvas graph={graph} selected={selected} onSelect={setSelected} /></div><aside className="entity-inspector"><div className="section-heading"><div><span className="eyebrow">Entity inspector</span><h3>{node?.id ?? "Select an endpoint"}</h3></div>{node ? <StatusBadge value={node.alerts ? "HIGH" : "READY"} /> : null}</div>{node ? <><dl className="entity-facts"><div><dt>Type</dt><dd>{label(node.kind)}</dd></div><div><dt>Connections</dt><dd>{node.connections}</dd></div><div><dt>Transferred</dt><dd>{bytes(node.bytes)}</dd></div><div><dt>Alert matches</dt><dd>{node.alerts}</dd></div></dl><div className="inspector-section flush"><h4>Counterparts</h4>{counterpartIds(graph, node.id).slice(0, 12).map((id) => <button key={id} onClick={() => setSelected(id)}><code>{id}</code></button>)}</div><div className="inspector-section flush"><h4>Relationships</h4>{edges.slice(0, 8).map((edge) => <div className="edge-reading" key={edge.id}><span>{edge.flows} flows</span><strong>{bytes(edge.bytes)}</strong>{edge.severity ? <StatusBadge value={edge.severity} /> : null}</div>)}</div></> : <p className="compact-note">Select a sphere for an internal host or an octahedron for an external destination. The flow table remains the accessible equivalent.</p>}</aside></section><section className="flow-section"><div className="section-heading"><div><span className="eyebrow">Flow metadata</span><h3>Observed connections</h3></div><span>{flows.data?.count ?? 0} most recent</span></div><FlowTable flows={flows.data?.flows ?? []} onSelect={setSelected} /></section></div>;
}
