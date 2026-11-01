import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bell,
  CheckCheck,
  ChevronDown,
  Command,
  LogOut,
  Menu,
  Moon,
  Radio,
  Search,
  Settings,
  ShieldAlert,
  Sun,
  UserRound,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import { useToast } from "../context/ToastContext";
import { api } from "../lib/api";
import { cn, initials, relativeTime, ROLE_LABEL } from "../lib/utils";

const TITLES: Record<string, string> = {
  "/": "Executive overview",
  "/analyst": "Analyst workspace",
  "/incidents": "Incident response",
  "/hunting": "Threat hunting",
  "/reports": "Intelligence reports",
  "/feeds": "Feeds & sources",
  "/audit": "Audit trail",
  "/users": "Users & roles",
  "/settings": "Settings",
};

export function Topbar({ onMenu, onSearch }: { onMenu: () => void; onSearch: () => void }) {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const userPanelRef = useRef<HTMLDivElement>(null);

  const notifications = useQuery({
    queryKey: ["notifications"],
    queryFn: () => api.notifications(),
    refetchInterval: 45_000,
  });
  const badges = useQuery({
    queryKey: ["badges"],
    queryFn: () => api.badges(),
    refetchInterval: 30_000,
  });

  useEffect(() => {
    const close = (event: MouseEvent) => {
      const target = event.target as Node;
      if (panelRef.current && !panelRef.current.contains(target)) setNotificationsOpen(false);
      if (userPanelRef.current && !userPanelRef.current.contains(target)) setUserOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  useEffect(() => {
    setNotificationsOpen(false);
    setUserOpen(false);
  }, [location.pathname]);

  const unread = badges.data?.data.unread_notifications ?? 0;
  const items = notifications.data?.data ?? [];
  const title = TITLES[location.pathname] ?? "ThreatLens";

  const markAll = async () => {
    try {
      await api.readNotifications([], true);
      await queryClient.invalidateQueries({ queryKey: ["notifications"] });
      await queryClient.invalidateQueries({ queryKey: ["badges"] });
    } catch {
      toast.error("Could not update notifications");
    }
  };

  const openNotification = async (id: string, link: string | null, read: boolean) => {
    if (!read) {
      await api.readNotifications([id]).catch(() => undefined);
      await queryClient.invalidateQueries({ queryKey: ["notifications"] });
      await queryClient.invalidateQueries({ queryKey: ["badges"] });
    }
    setNotificationsOpen(false);
    if (link) navigate(link);
  };

  return (
    <header className="sticky top-0 z-30 flex h-[76px] items-center justify-between gap-3 border-b border-ink-600/40 bg-ink-950/75 px-4 backdrop-blur-xl lg:px-7">
      <div className="flex min-w-0 items-center gap-3">
        <button type="button" onClick={onMenu} className="btn-ghost h-9 w-9 px-0 lg:hidden" aria-label="Open navigation">
          <Menu className="h-4 w-4" />
        </button>
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-slate-600">
            <span>Sentinova</span>
            <span className="text-cyan-500/50">/</span>
            <span className="truncate text-slate-500">ThreatLens</span>
          </div>
          <h2 className="truncate text-sm font-semibold text-slate-100">{title}</h2>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onSearch}
          className="hidden h-9 items-center gap-2 rounded-xl border border-ink-600/60 bg-ink-850/60 px-3 text-xs text-slate-500 transition hover:border-cyan-400/30 hover:text-slate-300 sm:flex"
        >
          <Search className="h-3.5 w-3.5" />
          <span>Search intelligence</span>
          <span className="ml-4 flex items-center gap-0.5 rounded border border-ink-600/70 px-1 py-0.5 text-[10px]">
            <Command className="h-2.5 w-2.5" /> K
          </span>
        </button>
        <button type="button" onClick={onSearch} className="btn-ghost h-9 w-9 px-0 sm:hidden" aria-label="Search">
          <Search className="h-4 w-4" />
        </button>

        <button
          type="button"
          onClick={toggleTheme}
          className="btn-ghost h-9 w-9 px-0"
          aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          title={theme === "dark" ? "Light mode" : "Dark mode"}
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>

        <div className="hidden items-center gap-2 rounded-full border border-mint/20 bg-mint/5 px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.14em] text-mint md:flex">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-mint opacity-60" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-mint" />
          </span>
          Live
          <Radio className="h-3 w-3 opacity-60" />
        </div>

        <div className="relative" ref={panelRef}>
          <button
            type="button"
            onClick={() => {
              setNotificationsOpen((value) => !value);
              setUserOpen(false);
            }}
            className="btn-ghost relative h-9 w-9 px-0"
            aria-label="Notifications"
          >
            <Bell className="h-4 w-4" />
            {unread > 0 && (
              <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-500 px-1 font-mono text-[9px] font-bold text-white">
                {unread > 99 ? "99+" : unread}
              </span>
            )}
          </button>

          {notificationsOpen && (
            <div className="panel absolute right-0 top-12 z-50 w-[min(380px,calc(100vw-2rem))] overflow-hidden bg-ink-850/98 shadow-glow">
              <div className="flex items-center justify-between border-b border-ink-600/50 px-4 py-3">
                <div>
                  <p className="text-sm font-semibold text-white">Notifications</p>
                  <p className="text-[10px] text-slate-500">{unread} unread</p>
                </div>
                <button type="button" onClick={markAll} className="btn-ghost h-8 px-2 text-[11px]">
                  <CheckCheck className="h-3.5 w-3.5" /> Mark all
                </button>
              </div>
              <div className="max-h-[420px] overflow-y-auto">
                {items.length === 0 ? (
                  <div className="px-4 py-10 text-center text-xs text-slate-500">You are all caught up.</div>
                ) : (
                  items.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => openNotification(item.id, item.link, item.read)}
                      className={cn(
                        "flex w-full gap-3 border-b border-ink-700/40 px-4 py-3 text-left transition last:border-b-0 hover:bg-ink-800/60",
                        !item.read && "bg-cyan-400/[0.035]",
                      )}
                    >
                      <span className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", item.read ? "bg-slate-600" : "bg-cyan-400")} />
                      <span className="min-w-0">
                        <span className="block text-xs font-medium text-slate-200">{item.title}</span>
                        <span className="mt-1 block truncate text-[11px] text-slate-500">{item.body}</span>
                        <span className="mt-1 block text-[10px] text-slate-600">{relativeTime(item.created_at)}</span>
                      </span>
                    </button>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        <div className="relative" ref={userPanelRef}>
          <button
            type="button"
            onClick={() => {
              setUserOpen((value) => !value);
              setNotificationsOpen(false);
            }}
            className="flex h-9 items-center gap-2 rounded-xl border border-ink-600/60 bg-ink-850/60 pl-1.5 pr-2.5 transition hover:border-ink-600"
          >
            <span className="flex h-6 w-6 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400/25 to-violet/25 text-[10px] font-semibold text-cyan-100">
              {initials(user?.name ?? "TL")}
            </span>
            <span className="hidden text-left sm:block">
              <span className="block max-w-[120px] truncate text-[11px] font-medium text-slate-200">{user?.name}</span>
              <span className="block text-[9px] uppercase tracking-[0.12em] text-slate-500">
                {user ? ROLE_LABEL[user.role] : ""}
              </span>
            </span>
            <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
          </button>

          {userOpen && (
            <div className="panel absolute right-0 top-12 z-50 w-60 overflow-hidden bg-ink-850/98 p-2 shadow-glow">
              <div className="border-b border-ink-600/50 px-3 py-2.5">
                <p className="truncate text-xs font-medium text-slate-200">{user?.email}</p>
                <p className="mt-1 text-[10px] text-slate-500">Clearance: {user ? ROLE_LABEL[user.role] : "—"}</p>
              </div>
              <button
                type="button"
                onClick={() => navigate("/settings")}
                className="mt-1 flex w-full items-center gap-2 rounded-lg px-3 py-2 text-xs text-slate-300 transition hover:bg-ink-700/50"
              >
                <Settings className="h-3.5 w-3.5" /> Settings
              </button>
              <button
                type="button"
                onClick={() => navigate("/settings")}
                className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-xs text-slate-300 transition hover:bg-ink-700/50"
              >
                <UserRound className="h-3.5 w-3.5" /> Profile
              </button>
              <button
                type="button"
                onClick={() => navigate("/analyst")}
                className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-xs text-slate-300 transition hover:bg-ink-700/50"
              >
                <ShieldAlert className="h-3.5 w-3.5" /> Alert queue
              </button>
              <button
                type="button"
                onClick={() => {
                  setUserOpen(false);
                  void logout().then(() => navigate("/login"));
                }}
                className="mt-1 flex w-full items-center gap-2 rounded-lg border-t border-ink-600/40 px-3 py-2 text-xs text-rose-300 transition hover:bg-rose-500/10"
              >
                <LogOut className="h-3.5 w-3.5" /> Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
