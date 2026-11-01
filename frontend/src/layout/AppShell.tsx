import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { CommandPalette } from "../components/CommandPalette";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { useWebSocket, type LiveEvent } from "../hooks/useWebSocket";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

export function AppShell() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("tl_sidebar") === "collapsed");
  const [searchOpen, setSearchOpen] = useState(false);
  const { user } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const location = useLocation();

  const onLiveEvent = (event: LiveEvent) => {
    if (event.topic === "alerts.stream" || event.topic === "alerts.new") {
      const title = typeof event.data.title === "string" ? event.data.title : "New alert received";
      toast.info(title, "The analyst queue and dashboards have been updated.");
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["analyst"] });
      void queryClient.invalidateQueries({ queryKey: ["executive"] });
      void queryClient.invalidateQueries({ queryKey: ["badges"] });
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    } else if (event.topic === "indicators.high_severity") {
      const value = typeof event.data.value === "string" ? event.data.value : "High-severity indicator";
      toast.info("High-severity indicator", value);
      void queryClient.invalidateQueries({ queryKey: ["indicators"] });
      void queryClient.invalidateQueries({ queryKey: ["executive"] });
    } else if (event.topic.startsWith("incidents.")) {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["incident"] });
      void queryClient.invalidateQueries({ queryKey: ["timeline"] });
    }
  };

  useWebSocket(onLiveEvent, Boolean(user));

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen((value) => !value);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  const toggleCollapsed = () => {
    setCollapsed((value) => {
      const next = !value;
      localStorage.setItem("tl_sidebar", next ? "collapsed" : "expanded");
      return next;
    });
  };

  return (
    <div className="relative flex min-h-screen">
      <div className="pointer-events-none fixed inset-0 z-0 bg-grid bg-[size:46px_46px] opacity-40 [mask-image:radial-gradient(ellipse_at_center,black,transparent_80%)]" />
      <div className="pointer-events-none fixed -left-40 top-0 z-0 h-[480px] w-[480px] rounded-full bg-cyan-400/[0.045] blur-3xl" />
      <div className="pointer-events-none fixed -right-32 top-1/3 z-0 h-[420px] w-[420px] rounded-full bg-violet/[0.04] blur-3xl" />
      <Sidebar
        open={sidebarOpen}
        collapsed={collapsed}
        onToggle={toggleCollapsed}
        onNavigate={() => setSidebarOpen(false)}
      />
      <div className="relative z-10 flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setSidebarOpen(true)} onSearch={() => setSearchOpen(true)} />
        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 lg:px-7 lg:py-8">
          <Outlet />
        </main>
        <footer className="border-t border-ink-600/30 px-4 py-4 text-[10px] text-slate-600 lg:px-7">
          <div className="flex flex-col justify-between gap-1 sm:flex-row">
            <span>Sentinova ThreatLens · CTI operations console</span>
            <span>
              Synthetic demonstration data · TLP handling enforced · audit chain active
            </span>
          </div>
        </footer>
      </div>
      <CommandPalette open={searchOpen} onClose={() => setSearchOpen(false)} />
    </div>
  );
}
