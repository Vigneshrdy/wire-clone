"use client";

import { Command, Menu, Moon, Search } from "lucide-react";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import { useSyncExternalStore } from "react";
import { ConnectionStatus } from "../status/connection-status";
import { useOperator } from "@/lib/security/operator-context";
import { label } from "@/lib/format";

const subscribe = () => () => {};

export function Topbar({ onMenu }: { onMenu: () => void }) {
  const pathname = usePathname();
  const { setTheme, resolvedTheme } = useTheme();
  const { unlocked } = useOperator();
  const mounted = useSyncExternalStore(subscribe, () => true, () => false);
  const section = pathname.split("/")[1] || "overview";

  return <header className="topbar"><div className="title-cluster"><button className="icon-button mobile-menu" onClick={onMenu} aria-label="Open navigation"><Menu size={19} /></button><div><span className="breadcrumb">Monitor /</span><h1>{label(section)}</h1></div></div><div className="topbar-tools"><button className="command-trigger" onClick={() => window.dispatchEvent(new Event("open-command"))}><Search size={15} /><span>Search or jump</span><kbd><Command size={11} />K</kbd></button><ConnectionStatus /><span className="operator-state" data-unlocked={unlocked}>{unlocked ? "Operator unlocked" : "Operator locked"}</span><button className="icon-button" onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")} aria-label="Toggle theme">{mounted ? <Moon size={17} /> : null}</button></div></header>;
}
