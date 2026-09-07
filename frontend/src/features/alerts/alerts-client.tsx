"use client";

import { useQuery } from "@tanstack/react-query";
import { Filter, RefreshCw, Search, X } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { queries } from "@/lib/api/queries";
import type { Alert } from "@/lib/api/schemas";
import { useAlertStream } from "@/lib/websocket/use-alert-stream";
import { AlertInspector } from "./alert-inspector";
import { AlertTable } from "./alert-table";

export function AlertsClient({ initialAlertId }: { initialAlertId?: string }) {
  const router = useRouter();
  const params = useSearchParams();
  const [selected, setSelected] = useState<Alert | undefined>();
  const filters = Object.fromEntries(params.entries());
  const query = useQuery({ queryKey: ["alerts", filters], queryFn: () => queries.alerts(filters), refetchInterval: 20_000 });
  const stream = useAlertStream();
  const selectedId = initialAlertId ?? selected?.alert_id;
  const setFilter = (key: string, value: string) => { const next = new URLSearchParams(params); if (value) next.set(key, value); else next.delete(key); router.replace(`/alerts${next.size ? `?${next}` : ""}`); };
  return <div className="alerts-page"><header className="page-heading"><div><h2>Alert investigation</h2><p>Prioritized detector verdicts with evidence and immutable lineage.</p></div><span className={`live-label live-${stream}`}><i />{stream}</span></header><div className="filter-toolbar"><Filter size={15} /><select aria-label="Severity" value={filters.severity ?? ""} onChange={(event) => setFilter("severity", event.target.value)}><option value="">All severity</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((item) => <option key={item}>{item}</option>)}</select><select aria-label="Threat" value={filters.threat_class ?? ""} onChange={(event) => setFilter("threat_class", event.target.value)}><option value="">All threats</option>{["DDOS", "C2_BEACON", "DGA", "DNS_TUNNEL", "TLS_MALWARE", "RECON", "EXFILTRATION"].map((item) => <option key={item}>{item}</option>)}</select><select aria-label="Status" value={filters.status ?? ""} onChange={(event) => setFilter("status", event.target.value)}><option value="">All status</option>{["NEW", "TRIAGED", "CONFIRMED", "DISMISSED", "SUPPRESSED"].map((item) => <option key={item}>{item}</option>)}</select><label className="filter-input"><Search size={14} /><input aria-label="Source IP" placeholder="Source IP" value={filters.src_ip ?? ""} onChange={(event) => setFilter("src_ip", event.target.value)} /></label><label className="filter-input confidence-filter"><span>Confidence</span><input type="number" min="0" max="1" step="0.1" aria-label="Minimum confidence" value={filters.min_confidence ?? ""} onChange={(event) => setFilter("min_confidence", event.target.value)} /></label><button className="tool-button" onClick={() => query.refetch()}><RefreshCw size={14} />Refresh</button>{params.size ? <button className="tool-button" onClick={() => router.replace("/alerts")}><X size={14} />Clear</button> : null}<span className="result-count mono">{query.data?.count ?? 0} shown</span></div><div className="investigation-layout" data-open={Boolean(selectedId)}><div className="alert-ledger"><AlertTable alerts={query.data?.alerts ?? []} selected={selectedId} onSelect={(alert) => { setSelected(alert); if (initialAlertId) router.push(`/alerts/${alert.alert_id}`); }} /></div><AlertInspector alertId={selectedId} fallback={selected} onClose={initialAlertId ? () => router.push("/alerts") : () => setSelected(undefined)} /></div></div>;
}
