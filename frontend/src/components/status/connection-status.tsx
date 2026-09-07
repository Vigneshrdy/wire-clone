"use client";

import { useQuery } from "@tanstack/react-query";
import { queries } from "@/lib/api/queries";
import { clsx } from "clsx";

export function ConnectionStatus({ compact = false }: { compact?: boolean }) {
  const ready = useQuery({ queryKey: ["ready"], queryFn: queries.ready, refetchInterval: 15_000 });
  const state = ready.isError ? "offline" : ready.data?.status === "degraded" ? "degraded" : ready.data ? "operational" : "connecting";
  return <span className={clsx("connection-status", `status-${state}`)} title={state === "degraded" ? "Historical data is available; streaming dependency is degraded" : undefined}><i />{compact ? null : <span>{state}</span>}</span>;
}
