import { ArrowRight, Command, Search, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import type { Indicator } from "../lib/types";
import { SEVERITY, shortValue, typeLabel } from "../lib/utils";
import { Modal } from "./ui";

const ROUTES = [
  { label: "Executive overview", path: "/", hint: "Risk posture and trends" },
  { label: "Analyst workspace", path: "/analyst", hint: "Alert triage queue" },
  { label: "Incidents", path: "/incidents", hint: "Investigation workspace" },
  { label: "Threat hunting", path: "/hunting", hint: "Search and ATT&CK" },
  { label: "Reports", path: "/reports", hint: "PDF intelligence briefs" },
  { label: "Feeds & sources", path: "/feeds", hint: "Connectors and health" },
  { label: "Audit trail", path: "/audit", hint: "Tamper-evident actions" },
  { label: "Settings", path: "/settings", hint: "Profile and security" },
];

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Indicator[]>([]);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setResults([]);
    window.setTimeout(() => inputRef.current?.focus(), 60);
  }, [open]);

  useEffect(() => {
    if (!open || query.trim().length < 2) {
      setResults([]);
      return;
    }
    let cancelled = false;
    setLoading(true);
    const timer = window.setTimeout(async () => {
      try {
        const response = await api.search({ q: query.trim(), size: 6 });
        if (!cancelled) setResults(response.data);
      } catch {
        if (!cancelled) setResults([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, 220);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [query, open]);

  const routes = useMemo(
    () => ROUTES.filter((route) => route.label.toLowerCase().includes(query.toLowerCase())).slice(0, 4),
    [query],
  );

  const go = (path: string) => {
    onClose();
    navigate(path);
  };

  return (
    <Modal open={open} onClose={onClose} title="Command center" description="Search intelligence or jump to a workspace." width="max-w-2xl">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3.5 top-3.5 h-4 w-4 text-slate-500" />
        <input
          ref={inputRef}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search IPs, domains, hashes, CVEs, or type a page name…"
          className="input pl-10 pr-16"
          autoComplete="off"
        />
        <span className="absolute right-3 top-2.5 hidden items-center gap-1 rounded border border-ink-600/70 px-1.5 py-0.5 text-[10px] text-slate-500 sm:flex">
          <Command className="h-3 w-3" /> K
        </span>
      </div>

      <div className="mt-4 max-h-[52vh] space-y-5 overflow-y-auto pr-1">
        {routes.length > 0 && (
          <div>
            <p className="label mb-2">Navigate</p>
            <div className="space-y-1">
              {routes.map((route) => (
                <button
                  key={route.path}
                  type="button"
                  onClick={() => go(route.path)}
                  className="flex w-full items-center justify-between rounded-xl border border-transparent px-3 py-2.5 text-left transition hover:border-ink-600/60 hover:bg-ink-800/60"
                >
                  <span className="flex items-center gap-3">
                    <ArrowRight className="h-4 w-4 text-cyan-400/70" />
                    <span>
                      <span className="block text-sm text-slate-200">{route.label}</span>
                      <span className="block text-[11px] text-slate-500">{route.hint}</span>
                    </span>
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}

        <div>
          <p className="label mb-2 flex items-center justify-between">
            <span>Intelligence</span>
            {loading && <span className="text-cyan-400/70">searching…</span>}
          </p>
          {results.length === 0 ? (
            <div className="rounded-xl border border-dashed border-ink-600/60 px-4 py-8 text-center text-xs text-slate-500">
              {query.trim().length < 2 ? "Type at least two characters to search the intelligence corpus." : "No matching indicators."}
            </div>
          ) : (
            <div className="space-y-1">
              {results.map((indicator) => {
                const meta = SEVERITY[indicator.severity];
                return (
                  <button
                    key={indicator.id}
                    type="button"
                    onClick={() => go(`/hunting?indicator=${indicator.id}`)}
                    className="flex w-full items-center gap-3 rounded-xl border border-transparent px-3 py-2.5 text-left transition hover:border-ink-600/60 hover:bg-ink-800/60"
                  >
                    <span className={`h-8 w-1 rounded-full ${meta.dot}`} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-xs text-slate-200">
                        {shortValue(indicator.value, 68)}
                      </span>
                      <span className="mt-0.5 block text-[10px] text-slate-500">
                        {typeLabel(indicator.type)} · {indicator.country || "unknown origin"} · {indicator.source_count} sources
                      </span>
                    </span>
                    <span className={`chip ${meta.bg} ${meta.border} ${meta.text}`}>
                      <ShieldAlert className="h-3 w-3" /> {indicator.severity_score}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}
