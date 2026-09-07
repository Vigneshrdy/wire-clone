export type MetricSample = { name: string; labels: Record<string, string>; value: number };

export function parseMetrics(text: string): MetricSample[] {
  return text.split("\n").filter((line) => line && !line.startsWith("#")).flatMap((line) => {
    const match = line.match(/^([a-zA-Z_:][\w:]*)?(?:\{([^}]*)\})?\s+(-?(?:\d+(?:\.\d+)?|\.\d+)(?:e[+-]?\d+)?|NaN|[+-]Inf)$/i);
    if (!match || !match[1]) return [];
    const labels: Record<string, string> = {};
    match[2]?.split(",").forEach((part) => { const item = part.match(/^([^=]+)="(.*)"$/); if (item) labels[item[1]] = item[2]; });
    return [{ name: match[1], labels, value: Number(match[3]) }];
  });
}

export const metricTotal = (samples: MetricSample[], name: string) => samples.filter((sample) => sample.name === name).reduce((sum, sample) => sum + sample.value, 0);
