import {
  Activity,
  ChevronLeft,
  FileText,
  Fingerprint,
  LayoutDashboard,
  Radar,
  Rss,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Swords,
  Users,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { NavLink } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { api } from "../lib/api";
import { cn } from "../lib/utils";

const NAV = [
  { to: "/", label: "Executive overview", icon: LayoutDashboard, permission: "view_dashboards", end: true },
  { to: "/analyst", label: "Analyst workspace", icon: ShieldAlert, permission: "manage_alerts" },
  { to: "/incidents", label: "Incidents", icon: Swords, permission: "read_incidents" },
  { to: "/hunting", label: "Threat hunting", icon: Radar, permission: "search" },
  { to: "/reports", label: "Reports", icon: FileText, permission: "generate_reports" },
  { to: "/feeds", label: "Feeds & sources", icon: Rss, permission: "configure_feeds" },
  { to: "/audit", label: "Audit trail", icon: ScrollText, permission: "view_audit" },
  { to: "/users", label: "Users & roles", icon: Users, permission: "manage_users" },
  { to: "/settings", label: "Settings", icon: Settings, permission: "view_dashboards" },
];

export function Sidebar({
  open,
  collapsed,
  onToggle,
  onNavigate,
}: {
  open: boolean;
  collapsed: boolean;
  onToggle: () => void;
  onNavigate: () => void;
}) {
  const { has } = useAuth();
  const meta = useQuery({ queryKey: ["meta"], queryFn: api.meta, staleTime: 60_000 });
  const metaData = meta.data?.data;

  return (
    <>
      <div
        className={cn(
          "fixed inset-0 z-40 bg-ink-950/75 backdrop-blur-sm transition lg:hidden",
          open ? "opacity-100" : "pointer-events-none opacity-0",
        )}
        onClick={onNavigate}
        aria-hidden="true"
      />
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex flex-col border-r border-ink-600/50 bg-ink-900/95 backdrop-blur-xl transition-all duration-300 lg:static lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
          collapsed ? "w-[76px]" : "w-[258px]",
        )}
      >
        <div className={cn("flex h-[76px] items-center border-b border-ink-600/50", collapsed ? "justify-center px-3" : "px-5")}>
          <NavLink to="/" onClick={onNavigate} className="flex items-center gap-3 overflow-hidden">
            <div className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/25 bg-cyan-400/10">
              <Fingerprint className="h-5 w-5 text-cyan-300" />
              <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-mint shadow-[0_0_8px_#34d399]" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold tracking-[0.14em] text-white">THREATLENS</div>
                <div className="truncate text-[9px] font-medium uppercase tracking-[0.26em] text-slate-500">
                  Sentinova intelligence
                </div>
              </div>
            )}
          </NavLink>
        </div>

        <nav className="scrollbar-none flex-1 space-y-1 overflow-y-auto px-3 py-5">
          {!collapsed && <p className="label mb-2 px-3">Operations</p>}
          {NAV.filter((item) => has(item.permission)).map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={onNavigate}
                title={collapsed ? item.label : undefined}
                className={({ isActive }) =>
                  cn("nav-link group", isActive && "nav-link-active", collapsed && "justify-center px-2")
                }
              >
                <Icon className="h-[18px] w-[18px] shrink-0" />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </NavLink>
            );
          })}

          {!collapsed && (
            <div className="mt-8 rounded-2xl border border-ink-600/60 bg-ink-850/60 p-3">
              <div className="flex items-center gap-2 text-[11px] font-medium text-slate-300">
                <ShieldCheck className="h-4 w-4 text-mint" />
                Intelligence fabric
              </div>
              <div className="mt-2 space-y-1.5 text-[10px] text-slate-500">
                <div className="flex items-center justify-between">
                  <span>Feeds enabled</span>
                  <span className="font-mono text-mint">
                    {metaData ? `${metaData.feeds_enabled} / ${metaData.feeds_total}` : "..."}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>ATT&CK coverage</span>
                  <span className="font-mono text-cyan-300">
                    {metaData ? `${metaData.attack_techniques} TTPs` : "..."}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Audit integrity</span>
                  <span className="font-mono text-mint">hash-chained</span>
                </div>
              </div>
            </div>
          )}
        </nav>

        <div className={cn("border-t border-ink-600/50 p-3", collapsed && "flex justify-center")}>
          <button
            type="button"
            onClick={onToggle}
            className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-[11px] text-slate-500 transition hover:bg-ink-700/40 hover:text-slate-200"
            aria-label="Toggle sidebar"
          >
            <ChevronLeft className={cn("h-4 w-4 transition", collapsed && "rotate-180")} />
            {!collapsed && <span>Collapse panel</span>}
          </button>
          {!collapsed && (
            <div className="mt-2 flex items-center gap-2 px-2 text-[10px] text-slate-600">
              <Activity className="h-3 w-3 text-mint" />
              <span>Single-node embedded profile</span>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
