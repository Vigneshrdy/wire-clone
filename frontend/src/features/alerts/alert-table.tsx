"use client";

import { createColumnHelper, flexRender, getCoreRowModel, getSortedRowModel, useReactTable, type SortingState } from "@tanstack/react-table";
import { useState } from "react";
import { StatusBadge } from "@/components/ui/status-badge";
import type { Alert } from "@/lib/api/schemas";
import { label, percent, utc } from "@/lib/format";

const helper = createColumnHelper<Alert>();
const columns = [
  helper.accessor("timestamp", { header: "Time", cell: (info) => <span className="mono">{utc(info.getValue(), true)}</span> }),
  helper.accessor("severity", { header: "Severity", cell: (info) => <StatusBadge value={info.getValue()} /> }),
  helper.accessor("threat_class", { header: "Threat", cell: (info) => <strong>{label(info.getValue())}</strong> }),
  helper.accessor("confidence", { header: "Confidence", cell: (info) => <span className="mono">{percent(info.getValue())}</span> }),
  helper.accessor("src_ip", { header: "Source", cell: (info) => <span className="mono">{info.getValue() ?? "—"}</span> }),
  helper.accessor("dst_ip", { header: "Destination", cell: (info) => <span className="mono">{info.getValue() ?? "—"}</span> }),
  helper.accessor("detector_name", { header: "Detector", cell: (info) => label(info.getValue()) }),
  helper.accessor("technique", { header: "Technique", cell: (info) => label(info.getValue()) }),
  helper.accessor("status", { header: "Status", cell: (info) => <StatusBadge value={info.getValue()} /> }),
  helper.accessor("incident_id", { header: "Incident", cell: (info) => <span className="mono">{info.getValue()?.slice(0, 8) ?? "—"}</span> }),
];

export function AlertTable({ alerts, selected, onSelect }: { alerts: Alert[]; selected?: string; onSelect: (alert: Alert) => void }) {
  const [sorting, setSorting] = useState<SortingState>([{ id: "timestamp", desc: true }]);
  // TanStack Table intentionally returns mutable table functions; React Compiler skips this component.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({ data: alerts, columns, state: { sorting }, onSortingChange: setSorting, getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel() });
  return <div className="data-region alert-table-region"><table className="data-table alert-table"><thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => <th key={header.id}><button className="sort-button" onClick={header.column.getToggleSortingHandler()}>{flexRender(header.column.columnDef.header, header.getContext())}<span>{header.column.getIsSorted() === "asc" ? "↑" : header.column.getIsSorted() === "desc" ? "↓" : ""}</span></button></th>)}</tr>)}</thead><tbody>{table.getRowModel().rows.map((row) => <tr key={row.id} className={row.original.alert_id === selected ? "selected" : ""} onClick={() => onSelect(row.original)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") onSelect(row.original); }}>{row.getVisibleCells().map((cell) => <td key={cell.id} className={cell.column.id === "threat_class" ? "primary-cell" : ""}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}{!alerts.length ? <tr><td colSpan={10} className="empty-row"><strong>No alerts match these filters.</strong><span>Clear filters or expand the time range.</span></td></tr> : null}</tbody></table></div>;
}
