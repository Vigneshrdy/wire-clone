"use client";

import { useEffect, useRef } from "react";
import type { EChartsOption } from "echarts";

export function EChart({ option, className = "chart" }: { option: EChartsOption; className?: string }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let disposed = false;
    let chart: import("echarts").ECharts | undefined;
    const observer = new ResizeObserver(() => chart?.resize());
    const themeObserver = new MutationObserver(() => chart?.setOption(resolveTokens(option), true));
    import("echarts").then((echarts) => {
      if (disposed || !host.current) return;
      chart = echarts.init(host.current, undefined, { renderer: "canvas" });
      chart.setOption(resolveTokens(option));
      observer.observe(host.current);
      themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    });
    return () => { disposed = true; observer.disconnect(); themeObserver.disconnect(); chart?.dispose(); };
  }, [option]);
  return <div className={className} ref={host} role="img" aria-label="Operational data chart" />;
}

function resolveTokens<T>(value: T): T {
  if (typeof value === "string" && value.startsWith("var(")) {
    const token = value.slice(4, -1);
    return getComputedStyle(document.documentElement).getPropertyValue(token).trim() as T;
  }
  if (Array.isArray(value)) return value.map(resolveTokens) as T;
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, resolveTokens(child)])) as T;
  return value;
}
