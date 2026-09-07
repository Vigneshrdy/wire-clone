"use client";

import { useState, type ReactNode } from "react";
import { Sidebar } from "./sidebar";
import { Topbar } from "./topbar";
import { CommandPalette } from "../command-palette/command-palette";

export function AppShell({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <div className="app-shell" data-collapsed={collapsed}>
      <Sidebar collapsed={collapsed} mobileOpen={mobileOpen} onCollapse={() => setCollapsed((value) => !value)} onNavigate={() => setMobileOpen(false)} />
      <div className="app-column">
        <Topbar onMenu={() => setMobileOpen(true)} />
        <main className="main-canvas">{children}</main>
      </div>
      <CommandPalette />
    </div>
  );
}
