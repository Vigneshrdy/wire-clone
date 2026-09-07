"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { useSyncExternalStore } from "react";

const subscribe = () => () => {};

export function ThemeControl() {
  const { theme, setTheme } = useTheme();
  const mounted = useSyncExternalStore(subscribe, () => true, () => false);
  if (!mounted) return <div className="theme-control" aria-hidden="true" />;
  return <div className="theme-control" aria-label="Color theme">{[["light", Sun], ["dark", Moon], ["system", Monitor]].map(([value, Icon]) => <button key={value as string} onClick={() => setTheme(value as string)} className={theme === value ? "active" : ""} title={value as string} aria-label={`${value} theme`}><Icon size={14} /></button>)}</div>;
}
