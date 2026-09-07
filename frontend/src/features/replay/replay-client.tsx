"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileSearch, Play } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { StatusBadge } from "@/components/ui/status-badge";
import { apiPost } from "@/lib/api/client";
import { queries } from "@/lib/api/queries";
import { label, number } from "@/lib/format";
import { useOperator } from "@/lib/security/operator-context";

const ReplayForm = z.object({ scenario: z.enum(["mixed", "benign", "ddos_syn", "ddos_udp_amp", "scan_vertical", "scan_horizontal", "c2_beacon", "dga", "dns_tunnel", "exfil"]), count: z.number().int().min(1).max(200000), seed: z.number().int(), pcap: z.string().max(1024).optional() });
type ReplayValues = z.infer<typeof ReplayForm>;

export function ReplayClient() {
  const { token, unlocked } = useOperator();
  const queryClient = useQueryClient();
  const [confirm, setConfirm] = useState(false);
  const [pendingReplay, setPendingReplay] = useState<ReplayValues>();
  const form = useForm<ReplayValues>({ resolver: zodResolver(ReplayForm), defaultValues: { scenario: "mixed", count: 3000, seed: 1337, pcap: "" } });
  const status = useQuery({ queryKey: ["replay"], queryFn: queries.replay, refetchInterval: (query) => query.state.data?.state === "running" ? 1000 : 5000 });
  const replay = useMutation({ mutationFn: (values: ReplayValues) => apiPost("replay/start", { ...values, pcap: values.pcap || null }, token), onSuccess: () => { toast.success("Safe replay started"); setConfirm(false); queryClient.invalidateQueries({ queryKey: ["replay"] }); }, onError: () => toast.error("Replay could not be started") });
  const state = String(status.data?.state ?? "idle");
  return <div><header className="page-heading"><div><h2>Lab control</h2><p>Run deterministic metadata through the passive pipeline without transmitting to a monitored network.</p></div><StatusBadge value={state} /></header><section className="replay-layout"><form className="surface replay-form" onSubmit={form.handleSubmit((data) => { setPendingReplay(data); setConfirm(true); })}><div className="section-heading"><div><span className="eyebrow">Synthetic replay</span><h3>Scenario configuration</h3></div><Play size={16} /></div><label>Scenario<select {...form.register("scenario")}>{["mixed", "benign", "ddos_syn", "ddos_udp_amp", "scan_vertical", "scan_horizontal", "c2_beacon", "dga", "dns_tunnel", "exfil"].map((item) => <option key={item} value={item}>{label(item)}</option>)}</select></label><div className="form-pair"><label>Event target<input type="number" {...form.register("count", { valueAsNumber: true })} /></label><label>Deterministic seed<input type="number" {...form.register("seed", { valueAsNumber: true })} /></label></div><label>PCAP reference <span>optional, server capture directory only</span><div className="input-icon"><FileSearch size={14} /><input placeholder="capture.pcap" {...form.register("pcap")} /></div></label><p className="passive-notice">Replay reads stored metadata or a server-side capture. It does not send packets.</p><button className="primary-button" type="submit" disabled={!unlocked || state === "running"}>Review and start</button>{!unlocked ? <p className="compact-note">Unlock operator mode in System to start a replay.</p> : null}</form><div className="surface replay-status"><div className="section-heading"><div><span className="eyebrow">Current run</span><h3>{label(state)}</h3></div><StatusBadge value={state} /></div>{state === "running" ? <div className="indeterminate"><i /></div> : null}<dl>{Object.entries(status.data ?? {}).filter(([key]) => key !== "state").map(([key, value]) => <div key={key}><dt>{label(key)}</dt><dd className={typeof value === "number" ? "mono" : ""}>{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd></div>)}</dl>{state === "idle" ? <p>No replay has started in this API process.</p> : null}</div></section><ConfirmDialog open={confirm} onOpenChange={setConfirm} title="Start passive replay" description="The run persists generated events and detector outputs. It cannot modify the monitored network." confirmLabel="Start replay" disabled={!pendingReplay || replay.isPending} onConfirm={() => pendingReplay && replay.mutate(pendingReplay)}><div className="confirmation-facts"><span>Scenario</span><strong>{label(pendingReplay?.scenario ?? "")}</strong><span>Event target</span><strong className="mono">{number(pendingReplay?.count, 0)}</strong><span>Seed</span><strong className="mono">{pendingReplay?.seed}</strong></div></ConfirmDialog></div>;
}
