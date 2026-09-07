"use client";

import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Clock3, Database, GitBranch, Radio, ShieldCheck, Waves } from "lucide-react";
import { useMemo } from "react";
import type { EChartsOption } from "echarts";
import Link from "next/link";
import { EChart } from "@/components/charts/echart";
import { EmptyRow } from "@/components/ui/empty-row";
import { QueryError } from "@/components/ui/query-state";
import { StatusBadge } from "@/components/ui/status-badge";
import { apiText } from "@/lib/api/client";
import { metricTotal, parseMetrics } from "@/lib/api/metrics";
import { queries } from "@/lib/api/queries";
import { label, number, percent, utc } from "@/lib/format";
import { useAlertStream } from "@/lib/websocket/use-alert-stream";

export function OverviewClient() {
  const ready = useQuery({ queryKey: ["ready"], queryFn: queries.ready, refetchInterval: 15_000 });
  const alerts = useQuery({ queryKey: ["alerts", "overview"], queryFn: () => queries.alerts({ limit: 50 }), refetchInterval: 20_000 });
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: queries.incidents, refetchInterval: 20_000 });
  const detectors = useQuery({ queryKey: ["detectors"], queryFn: queries.detectors, refetchInterval: 25_000 });
  const metrics = useQuery({ queryKey: ["metrics"], queryFn: () => apiText("metrics"), refetchInterval: 15_000 });
  const stream = useAlertStream();
  const samples = useMemo(() => parseMetrics(metrics.data ?? ""), [metrics.data]);
  const alertRows = useMemo(() => alerts.data?.alerts ?? [], [alerts.data]);
  const active = alertRows.filter((item) => item.status === "NEW" || item.status === "TRIAGED");
  const high = active.filter((item) => item.severity === "CRITICAL" || item.severity === "HIGH").length;
  const readyCount = Object.values(ready.data?.detectors ?? {}).filter((state) => state === "READY").length;
  const latest = alertRows[0]?.last_seen;
  const timeline = useMemo(() => {
    const buckets = new Map<string, { label: string; total: number; high: number }>();
    alertRows.slice().reverse().forEach((item) => { const time = new Date(item.timestamp); const key = `${time.getUTCHours()}:${String(Math.floor(time.getUTCMinutes() / 10) * 10).padStart(2, "0")}`; const entry = buckets.get(key) ?? { label: key, total: 0, high: 0 }; entry.total += 1; if (item.severity === "CRITICAL" || item.severity === "HIGH") entry.high += 1; buckets.set(key, entry); });
    return [...buckets.values()];
  }, [alertRows]);
  const chartOption = useMemo<EChartsOption>(() => ({
    backgroundColor: "transparent", animationDuration: 180,
    tooltip: { trigger: "axis", backgroundColor: "var(--surface-elevated)", borderColor: "var(--border-strong)", textStyle: { color: "var(--text-primary)", fontSize: 11 } },
    grid: { left: 34, right: 12, top: 16, bottom: 25 },
    xAxis: { type: "category", data: timeline.map((point) => point.label), boundaryGap: false, axisLine: { lineStyle: { color: "var(--border-subtle)" } }, axisLabel: { color: "var(--text-muted)", fontSize: 10 } },
    yAxis: { type: "value", minInterval: 1, axisLabel: { color: "var(--text-muted)", fontSize: 10 }, splitLine: { lineStyle: { color: "var(--border-subtle)" } } },
    series: [{ name: "Alerts", type: "line", data: timeline.map((point) => point.total), showSymbol: false, lineStyle: { color: "var(--accent)", width: 2 }, itemStyle: { color: "var(--accent)" } }, { name: "Critical / high", type: "bar", data: timeline.map((point) => point.high), itemStyle: { color: "var(--danger)" }, barMaxWidth: 10 }],
  }), [timeline]);

  return <div className="overview-page"><header className="page-heading"><div><h2>Operational picture</h2><p>Passive detection health and the most recent signals, synchronized in UTC.</p></div><span className={`live-label live-${stream}`}><i />{stream}</span></header>
    <section className="signal-spine" aria-label="Operational summary">
      <Metric icon={ShieldCheck} label="Detection" value={ready.data?.status === "ok" ? "Operational" : ready.data ? "Degraded" : "Offline"} />
      <Metric icon={Waves} label="Events observed" value={number(metricTotal(samples, "sih_events_received_total"), 0)} />
      <Metric icon={AlertTriangle} label="Open alerts" value={number(active.length, 0)} />
      <Metric icon={Activity} label="Critical / high" value={number(high, 0)} emphasis={high > 0} />
      <Metric icon={GitBranch} label="Incidents" value={number(incidents.data?.count, 0)} />
      <Metric icon={Radio} label="Ready detectors" value={`${readyCount}/${Object.keys(ready.data?.detectors ?? {}).length || 7}`} />
      <Metric icon={Database} label="Stream" value={ready.data?.redis ? "Connected" : "Degraded"} />
      <Metric icon={Clock3} label="Last alert" value={latest ? utc(latest, true).replace(" UTC", "") : "No activity"} />
    </section>
    <section className="overview-primary"><div className="surface activity-panel"><div className="section-heading"><div><span className="eyebrow">Threat activity</span><h3>Alert signal timeline</h3></div><span>10-minute UTC buckets</span></div>{alerts.isError ? <QueryError /> : timeline.length ? <EChart option={chartOption} className="overview-chart" /> : <div className="compact-empty">No alerts in the selected range.</div>}</div>
      <div className="surface readiness-panel"><div className="section-heading"><div><span className="eyebrow">Readiness</span><h3>Detection path</h3></div><StatusBadge value={ready.data?.status ?? "offline"} /></div><div className="readiness-list"><ReadinessRow name="API" value={ready.isError ? "OFFLINE" : "READY"} detail="Historical query service" /><ReadinessRow name="Redis" value={ready.data?.redis ? "READY" : "DEGRADED"} detail="Streaming event fabric" /><ReadinessRow name="Store" value={ready.data ? "READY" : "OFFLINE"} detail={`${number(Object.values(ready.data?.store.counts ?? {}).reduce((sum, value) => sum + value, 0), 0)} persisted rows`} /><ReadinessRow name="WebSocket" value={stream === "live" ? "READY" : stream === "reconnecting" ? "DEGRADED" : "OFFLINE"} detail="Future alert feed" /><ReadinessRow name="Detector mesh" value={readyCount ? "READY" : "DEGRADED"} detail={`${readyCount} accepting traffic`} /></div></div></section>
    <section className="overview-ledgers"><div className="surface ledger"><div className="section-heading"><h3>Live alert ledger</h3><Link href="/alerts">Open investigation</Link></div><div className="data-region"><table className="data-table"><thead><tr><th>Time</th><th>Severity</th><th>Signal</th><th>Subject</th><th className="numeric">Confidence</th><th>Status</th></tr></thead><tbody>{alertRows.slice(0, 8).map((item) => <tr key={item.alert_id}><td className="mono">{utc(item.timestamp, true)}</td><td><StatusBadge value={item.severity} /></td><td className="primary-cell">{label(item.threat_class)}</td><td className="mono">{item.entity_id}</td><td className="numeric">{percent(item.confidence)}</td><td><StatusBadge value={item.status} /></td></tr>)}{!alertRows.length ? <EmptyRow columns={6} title="No alerts in the selected range." /> : null}</tbody></table></div></div>
      <div className="surface ledger"><div className="section-heading"><h3>Active incidents</h3><Link href="/incidents">View queue</Link></div><div className="data-region"><table className="data-table"><thead><tr><th>Last seen</th><th>Primary signal</th><th>Entity</th><th className="numeric">Alerts</th></tr></thead><tbody>{incidents.data?.incidents.slice(0, 8).map((item) => <tr key={item.incident_id}><td className="mono">{utc(item.last_seen, true)}</td><td><StatusBadge value={item.primary_threat_class} /></td><td className="mono primary-cell">{item.entity_id}</td><td className="numeric">{item.alert_count}</td></tr>)}{!incidents.data?.incidents.length ? <EmptyRow columns={4} title="No correlated incidents in this time range." detail="Incidents form when multiple detector signals correlate on one subject." /> : null}</tbody></table></div></div></section>
    <section className="detector-rail"><div className="section-heading"><h3>Detector mesh</h3><span>All seven detectors remain visible</span></div><div className="detector-rail-grid">{detectors.data?.detectors.map((item) => <div className="detector-rail-item" key={item.name}><div><strong>{label(item.name)}</strong><span>{label(item.threat_class)} · {label(item.technique)}</span></div><StatusBadge value={item.state} /></div>)}</div></section>
  </div>;
}

function Metric({ icon: Icon, label: metricLabel, value, emphasis = false }: { icon: typeof Activity; label: string; value: string; emphasis?: boolean }) { return <div className="signal-cell" data-emphasis={emphasis}><Icon size={15} /><div><span>{metricLabel}</span><strong>{value}</strong></div></div>; }
function ReadinessRow({ name, value, detail }: { name: string; value: string; detail: string }) { return <div className="readiness-row"><span className="readiness-path"><i /><b /></span><div><strong>{name}</strong><span>{detail}</span></div><StatusBadge value={value} /></div>; }
