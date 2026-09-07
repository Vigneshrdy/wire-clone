export const number = (value: number | null | undefined, digits = 1) => value == null || !Number.isFinite(value) ? "—" : new Intl.NumberFormat(undefined, { maximumFractionDigits: digits, notation: Math.abs(value) >= 1_000_000 ? "compact" : "standard" }).format(value);
export const percent = (value: number | null | undefined) => value == null ? "—" : `${(value * 100).toFixed(1)}%`;
export const bytes = (value: number | null | undefined) => {
  if (value == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = value;
  let index = 0;
  while (Math.abs(amount) >= 1024 && index < units.length - 1) { amount /= 1024; index += 1; }
  return `${amount.toFixed(index ? 1 : 0)} ${units[index]}`;
};
export const utc = (value: string | number | null | undefined, compact = false) => {
  if (value == null) return "—";
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  if (Number.isNaN(date.valueOf())) return "—";
  return new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", day: compact ? undefined : "2-digit", month: compact ? undefined : "short", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(date) + " UTC";
};
export const label = (value: string) => value.replaceAll("_", " ").toLowerCase().replace(/^\w/, (character) => character.toUpperCase());
