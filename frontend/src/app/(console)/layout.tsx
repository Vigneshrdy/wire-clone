import { AppShell } from "@/components/app-shell/app-shell";
import "@/styles/console.css";

export default function ConsoleLayout({ children }: LayoutProps<"/">) {
  return <AppShell>{children}</AppShell>;
}
