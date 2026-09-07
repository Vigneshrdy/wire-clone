"use client";

import { Activity, AlertTriangle, BarChart3, BrainCircuit, ChevronLeft, ChevronRight, FlaskConical, GitBranch, LayoutDashboard, Menu, Network, Radar, ServerCog, Shapes, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { clsx } from "clsx";
import { ThemeControl } from "./theme-control";
import { ConnectionStatus } from "../status/connection-status";

const groups = [
  { label: "Monitor", items: [["Overview", "/overview", LayoutDashboard], ["Alerts", "/alerts", AlertTriangle], ["Incidents", "/incidents", GitBranch], ["Network", "/network", Network]] },
  { label: "Intelligence", items: [["Detectors", "/detectors", Radar], ["Models", "/models", BrainCircuit], ["Learning", "/learning", Shapes]] },
  { label: "Operations", items: [["Replay", "/replay", FlaskConical], ["Benchmarks", "/benchmarks", BarChart3], ["System", "/system", ServerCog]] },
] as const;

export function Sidebar({ collapsed, mobileOpen, onCollapse, onNavigate }: { collapsed: boolean; mobileOpen: boolean; onCollapse: () => void; onNavigate: () => void }) {
  const pathname = usePathname();
  return (
    <aside className={clsx("sidebar", mobileOpen && "sidebar-mobile-open")} aria-label="Primary navigation">
      <div className="product-mark"><span className="product-glyph"><Activity size={18} /></span><div><strong>SIH 26145</strong><span>Signal operations</span></div><button className="icon-button mobile-close" onClick={onNavigate} aria-label="Close navigation"><X size={18} /></button></div>
      <nav className="nav-groups">
        {groups.map((group) => <div className="nav-group" key={group.label}><span className="nav-label">{group.label}</span>{group.items.map(([name, href, Icon]) => <Link className={clsx("nav-link", pathname === href || pathname.startsWith(`${href}/`) ? "active" : "")} href={href} key={href} onClick={onNavigate} title={collapsed ? name : undefined}><Icon size={17} strokeWidth={1.8} /><span>{name}</span></Link>)}</div>)}
      </nav>
      <div className="sidebar-footer"><ThemeControl /><ConnectionStatus compact /><div className="build-info"><span>API v1</span><span>Console 0.1.0</span></div></div>
      <button className="collapse-button" onClick={onCollapse} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>{collapsed ? <ChevronRight size={15} /> : <><ChevronLeft size={15} /><span>Collapse</span></>}</button>
      <button className="mobile-menu-shadow" onClick={onNavigate} aria-label="Close menu"><Menu /></button>
    </aside>
  );
}
