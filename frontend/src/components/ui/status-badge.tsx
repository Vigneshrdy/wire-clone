import { clsx } from "clsx";
import { label } from "@/lib/format";

export function StatusBadge({ value }: { value: string }) {
  return <span className={clsx("status-badge", `tone-${value.toLowerCase().replaceAll("_", "-")}`)}><i />{label(value)}</span>;
}
