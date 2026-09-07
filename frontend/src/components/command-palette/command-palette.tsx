"use client";

import { Command } from "cmdk";
import { AlertTriangle, GitBranch, LayoutDashboard, Moon, Network, RefreshCw, ServerCog, Sun } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useEffect, useState } from "react";

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const router = useRouter();
  const { setTheme } = useTheme();
  useEffect(() => {
    const keyboard = (event: KeyboardEvent) => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setOpen((value) => !value); } };
    const custom = () => setOpen(true);
    window.addEventListener("keydown", keyboard); window.addEventListener("open-command", custom);
    return () => { window.removeEventListener("keydown", keyboard); window.removeEventListener("open-command", custom); };
  }, []);
  const run = (action: () => void) => { setOpen(false); action(); };
  return <Command.Dialog open={open} onOpenChange={setOpen} label="Command menu"><div className="command-dialog"><Command.Input placeholder="Type a command or route" /><Command.List><Command.Empty>No matching command.</Command.Empty><Command.Group heading="Navigate">{[["Overview", "/overview", LayoutDashboard], ["Alerts", "/alerts", AlertTriangle], ["Incidents", "/incidents", GitBranch], ["Network", "/network", Network], ["System", "/system", ServerCog]].map(([name, href, Icon]) => <Command.Item key={href as string} onSelect={() => run(() => router.push(href as string))}><Icon size={16} />Go to {name as string}</Command.Item>)}</Command.Group><Command.Group heading="Actions"><Command.Item onSelect={() => run(() => location.reload())}><RefreshCw size={16} />Refresh data</Command.Item><Command.Item onSelect={() => run(() => setTheme("light"))}><Sun size={16} />Use light theme</Command.Item><Command.Item onSelect={() => run(() => setTheme("dark"))}><Moon size={16} />Use dark theme</Command.Item></Command.Group></Command.List></div></Command.Dialog>;
}
