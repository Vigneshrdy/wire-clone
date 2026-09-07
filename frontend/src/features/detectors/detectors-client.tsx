"use client";

import { useQuery } from "@tanstack/react-query";
import { ChevronDown } from "lucide-react";
import { Fragment, useState } from "react";
import { StatusBadge } from "@/components/ui/status-badge";
import { queries } from "@/lib/api/queries";
import { label } from "@/lib/format";

export function DetectorsClient() {
  const query = useQuery({ queryKey: ["detectors"], queryFn: queries.detectors, refetchInterval: 25_000 });
  const [expanded, setExpanded] = useState<string>();
  const ready = query.data?.detectors.filter((item) => item.state === "READY").length ?? 0;
  return <div><header className="page-heading"><div><h2>Detector mesh</h2><p>Runtime capability inventory. Unavailable detectors remain explicit and do not fabricate verdicts.</p></div><span className="result-count mono">{ready}/{query.data?.detectors.length ?? 7} ready</span></header><section className="matrix-summary"><span><b>{ready}</b> accepting traffic</span><span><b>{(query.data?.detectors.length ?? 0) - ready}</b> unavailable or degraded</span><span><b>1.0.0</b> feature contract</span></section><div className="surface data-region detector-matrix"><table className="data-table"><thead><tr><th>Detector</th><th>State</th><th>Technique</th><th>Threat class</th><th>Version</th><th>Model</th><th>Feature schema</th><th>Reason</th><th></th></tr></thead><tbody>{query.data?.detectors.map((item) => <Fragment key={item.name}><tr onClick={() => setExpanded(expanded === item.name ? undefined : item.name)}><td className="primary-cell">{label(item.name)}</td><td><StatusBadge value={item.state} /></td><td>{label(item.technique)}</td><td>{label(item.threat_class)}</td><td className="mono">{item.detector_version}</td><td className="mono">{item.model_version ?? "Not required"}</td><td className="mono">{item.feature_schema_version}</td><td className="reason-cell">{item.state_reason ?? "Ready for evaluated feature vectors"}</td><td><ChevronDown size={14} className={expanded === item.name ? "rotated" : ""} /></td></tr>{expanded === item.name ? <tr className="expanded-row"><td colSpan={9}><div><span>Signal contract</span><strong>{label(item.threat_class)} via {label(item.technique)}</strong><span>Availability</span><strong>{item.state_reason ?? "Detector is loaded and accepting feature vectors."}</strong></div></td></tr> : null}</Fragment>)}</tbody></table></div></div>;
}
