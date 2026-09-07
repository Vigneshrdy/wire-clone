"use client";

import { useVirtualizer } from "@tanstack/react-virtual";
import { useRef } from "react";
import type { Flow } from "@/lib/api/schemas";
import { bytes, utc } from "@/lib/format";

export function FlowTable({ flows, onSelect }: { flows: Flow[]; onSelect: (id: string) => void }) {
  const parent = useRef<HTMLDivElement>(null);
  // TanStack Virtual intentionally returns mutable measurement functions; React Compiler skips this component.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtual = useVirtualizer({ count: flows.length, getScrollElement: () => parent.current, estimateSize: () => 39, overscan: 8 });
  return <div className="virtual-flow-table" ref={parent} role="table" aria-label="Observed flows"><div className="flow-grid flow-head" role="row"><span>Time</span><span>Source</span><span>Destination</span><span>Protocol</span><span>Service</span><span>Direction</span><span>Bytes</span><span>State</span></div><div className="virtual-flow-body" style={{ height: virtual.getTotalSize() }}>{virtual.getVirtualItems().map((row) => { const flow = flows[row.index]; return <button className="flow-grid flow-row" role="row" key={flow.event_id} style={{ transform: `translateY(${row.start}px)` }} onClick={() => onSelect(flow.src_ip)}><span className="mono">{utc(flow.ts, true)}</span><span className="mono">{flow.src_ip}:{flow.src_port ?? "—"}</span><span className="mono">{flow.dst_ip}:{flow.dst_port ?? "—"}</span><span>{flow.transport.toUpperCase()}</span><span>{flow.service ?? "—"}</span><span>{flow.direction}</span><span className="mono">{bytes(flow.orig_bytes + (flow.resp_bytes ?? 0))}</span><span>{flow.connection_state ?? "—"}</span></button>; })}</div>{!flows.length ? <div className="compact-empty flow-empty">No flow metadata is available.</div> : null}</div>;
}
