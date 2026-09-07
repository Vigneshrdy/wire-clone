"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ExternalLink, X } from "lucide-react";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { StatusBadge } from "@/components/ui/status-badge";
import { apiPost } from "@/lib/api/client";
import { queries } from "@/lib/api/queries";
import type { Alert } from "@/lib/api/schemas";
import { label, number, percent, utc } from "@/lib/format";
import { useOperator } from "@/lib/security/operator-context";

const FeedbackForm = z.object({ label: z.enum(["TRUE_POSITIVE", "FALSE_POSITIVE", "FALSE_NEGATIVE", "UNCERTAIN"]), analyst_id: z.string().min(1).max(256), notes: z.string().max(4096), corrected_threat_class: z.string().optional() });
type FeedbackValues = z.infer<typeof FeedbackForm>;

export function AlertInspector({ alertId, fallback, onClose }: { alertId?: string; fallback?: Alert; onClose?: () => void }) {
  const queryClient = useQueryClient();
  const { token, unlocked } = useOperator();
  const detail = useQuery({ queryKey: ["alert", alertId], queryFn: () => queries.alert(alertId!), enabled: Boolean(alertId) });
  const alert = detail.data?.alert ?? fallback;
  const form = useForm<FeedbackValues>({ resolver: zodResolver(FeedbackForm), defaultValues: { label: "UNCERTAIN", analyst_id: "analyst", notes: "" } });
  const status = useMutation({ mutationFn: (value: string) => apiPost(`alerts/${alertId}/status`, { status: value, actor: "console" }, token), onSuccess: () => { toast.success("Alert status updated"); queryClient.invalidateQueries({ queryKey: ["alerts"] }); queryClient.invalidateQueries({ queryKey: ["alert", alertId] }); }, onError: () => toast.error("Status update failed") });
  const feedback = useMutation({ mutationFn: (values: FeedbackValues) => apiPost("feedback", { ...values, alert_id: alertId, corrected_threat_class: values.corrected_threat_class || null }, token), onSuccess: () => { toast.success("Stored as training candidate. Production models were not modified."); form.reset(); }, onError: () => toast.error("Feedback could not be stored") });
  if (!alert) return <aside className="alert-inspector inspector-placeholder"><div><strong>Select an alert to investigate</strong><span>Evidence, baselines, lineage, and analyst actions will remain beside the ledger.</span></div></aside>;
  const readings = evidenceReadings(alert);
  return <aside className="alert-inspector"><div className="inspector-top"><div><StatusBadge value={alert.severity} /><h2>{label(alert.threat_class)}</h2><p>{alert.evidence.summary}</p></div><div className="inspector-actions">{alertId ? <Link href={`/alerts/${alertId}`} aria-label="Open alert route"><ExternalLink size={15} /></Link> : null}{onClose ? <button onClick={onClose} aria-label="Close inspector"><X size={16} /></button> : null}</div></div>
    <div className="inspector-tabs" role="tablist"><span className="active">Evidence</span><span>Lineage</span><span>History</span></div>
    <section className="inspector-section"><dl className="fact-grid"><div><dt>Subject</dt><dd className="mono">{alert.entity_id}</dd></div><div><dt>Confidence</dt><dd className="mono">{percent(alert.confidence)}</dd></div><div><dt>Detector</dt><dd>{label(alert.detector_name)}</dd></div><div><dt>Technique</dt><dd>{label(alert.technique)}</dd></div><div><dt>First seen</dt><dd className="mono">{utc(alert.first_seen)}</dd></div><div><dt>Last seen</dt><dd className="mono">{utc(alert.last_seen)}</dd></div></dl></section>
    <section className="inspector-section"><div className="section-heading"><h3>Why this fired</h3><span>{alert.evidence.reason_codes.length} reasons</span></div><div className="reason-list">{alert.evidence.reason_codes.map((reason) => <div key={reason}><CheckCircle2 size={14} /><span>{label(reason)}</span></div>)}</div></section>
    <section className="inspector-section"><div className="section-heading"><h3>Observed against expected</h3><span>Exact detector evidence</span></div>{readings.map((item) => <EvidenceScale key={item.name} {...item} />)}{!readings.length ? <p className="compact-note">No numeric comparison was attached to this alert.</p> : null}</section>
    <section className="inspector-section"><div className="section-heading"><h3>Flow references</h3><span>{alert.evidence.flow_ids.length}</span></div><div className="reference-list">{alert.evidence.flow_ids.slice(0, 12).map((id) => <code key={id}>{id}</code>)}{alert.evidence.flow_ids.length > 12 ? <span>+{alert.evidence.flow_ids.length - 12} more</span> : null}</div></section>
    <section className="inspector-section"><div className="section-heading"><h3>Lineage</h3><span>Reproducible verdict</span></div><dl className="lineage-list"><div><dt>Detector version</dt><dd className="mono">{alert.detector_version}</dd></div><div><dt>Feature schema</dt><dd className="mono">{alert.feature_schema_version}</dd></div><div><dt>Confidence basis</dt><dd>{label(alert.confidence_basis)}</dd></div><div><dt>Pipeline run</dt><dd className="mono">{alert.lineage.pipeline_run_id ?? "—"}</dd></div></dl></section>
    {detail.data?.history.length ? <section className="inspector-section"><div className="section-heading"><h3>Decision history</h3><span>{detail.data.history.length} records</span></div><div className="history-list">{detail.data.history.map((entry, index) => <div key={`${entry.kind}-${index}`}><i /><strong>{label(entry.kind)}</strong><time>{utc(entry.timestamp)}</time></div>)}</div></section> : null}
    <section className="inspector-section analyst-actions"><div className="section-heading"><h3>Analyst action</h3><StatusBadge value={unlocked ? "READY" : "UNAVAILABLE"} /></div><div className="button-row"><button disabled={!unlocked || status.isPending} onClick={() => status.mutate("CONFIRMED")}>Confirm</button><button disabled={!unlocked || status.isPending} onClick={() => status.mutate("DISMISSED")}>Dismiss</button></div><form onSubmit={form.handleSubmit((values) => feedback.mutate(values))}><label>Judgement<select {...form.register("label")} disabled={!unlocked}><option value="TRUE_POSITIVE">True positive</option><option value="FALSE_POSITIVE">False positive</option><option value="FALSE_NEGATIVE">False negative</option><option value="UNCERTAIN">Uncertain</option></select></label><label>Analyst ID<input {...form.register("analyst_id")} disabled={!unlocked} /></label><label className="full-field">Notes<textarea {...form.register("notes")} rows={2} disabled={!unlocked} /></label><button className="primary-button" type="submit" disabled={!unlocked || feedback.isPending}>Store feedback</button></form>{!unlocked ? <p className="compact-note">Unlock operator mode in System to submit management actions.</p> : null}</section>
  </aside>;
}

type Reading = { name: string; observed: number; baseline?: number; threshold?: number };
export function evidenceReadings(alert: Alert): Reading[] {
  const baseline = alert.evidence.baseline_comparisons;
  return Object.entries(alert.evidence.observations).slice(0, 8).map(([name, observed]) => {
    const root = name.replace(/_(1s|5s|30s|60s|300s)$/, "");
    const baselineValue = Object.entries(baseline).find(([key]) => key.includes(root) && key.includes("baseline_mean"))?.[1];
    const threshold = Object.entries(baseline).find(([key]) => key.includes(root) && key.includes("threshold"))?.[1] ?? Object.entries(baseline).find(([key]) => key.endsWith("threshold"))?.[1];
    return { name, observed, baseline: baselineValue, threshold };
  });
}

function EvidenceScale({ name, observed, baseline, threshold }: Reading) {
  const max = Math.max(Math.abs(observed), Math.abs(baseline ?? 0), Math.abs(threshold ?? 0), 1);
  return <div className="evidence-scale"><div><strong>{label(name)}</strong><span className="mono">{number(observed, 2)}</span></div><div className="scale-track"><i className="scale-baseline" style={{ left: `${Math.min(100, Math.abs(baseline ?? 0) / max * 100)}%` }} /><i className="scale-threshold" style={{ left: `${Math.min(100, Math.abs(threshold ?? 0) / max * 100)}%` }} /><b style={{ width: `${Math.min(100, Math.abs(observed) / max * 100)}%` }} /></div><div className="scale-legend"><span>Baseline {number(baseline, 2)}</span><span>Threshold {number(threshold, 2)}</span><span>Observed {number(observed, 2)}</span></div></div>;
}
