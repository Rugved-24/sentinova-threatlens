import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  BellRing,
  CheckCircle2,
  Filter,
  Inbox,
  Search,
  Settings2,
  ShieldAlert,
  Sparkles,
  UserRound,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AlertDrawer } from "../components/AlertDrawer";
import { IndicatorDrawer } from "../components/IndicatorDrawer";
import {
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  Modal,
  PageHeader,
  Pagination,
  SectionCard,
  SeverityBadge,
  StatCard,
  StatusBadge,
  TlpBadge,
  Toggle,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import { cn, relativeTime, shortValue } from "../lib/utils";

const STATUS_OPTIONS = ["new", "acknowledged", "in-progress", "resolved", "closed"];
const SEVERITY_OPTIONS = ["critical", "high", "medium", "low"];

export function Analyst() {
  const { has } = useAuth();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [selectedAlert, setSelectedAlert] = useState<string | null>(searchParams.get("alert"));
  const [selectedIndicator, setSelectedIndicator] = useState<string | null>(null);
  const [rulesOpen, setRulesOpen] = useState(false);

  const dashboard = useQuery({ queryKey: ["analyst"], queryFn: api.analyst, refetchInterval: 30_000 });
  const alerts = useQuery({
    queryKey: ["alerts", { page, status, severity, q: search }],
    queryFn: () => api.alerts({ page, size: 20, status: status || undefined, severity: severity || undefined, q: search || undefined }),
    refetchInterval: 30_000,
  });

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearch(query.trim());
      setPage(1);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    const alertParam = searchParams.get("alert");
    if (alertParam) setSelectedAlert(alertParam);
  }, [searchParams]);

  const closeAlert = () => {
    setSelectedAlert(null);
    if (searchParams.has("alert")) {
      const next = new URLSearchParams(searchParams);
      next.delete("alert");
      setSearchParams(next, { replace: true });
    }
  };

  const counters = dashboard.data?.data.counters;
  const queue = alerts.data?.data ?? [];

  const quickFilter = (next: { status?: string; severity?: string }) => {
    if (next.status !== undefined) setStatus(next.status);
    if (next.severity !== undefined) setSeverity(next.severity);
    setPage(1);
  };

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="SOC operations"
        title="Analyst workspace"
        description="Triage incoming alerts, validate indicators and route confirmed activity into incident response. Every decision is auditable."
        actions={
          <>
            {has("manage_rules") && (
              <button type="button" className="btn-ghost" onClick={() => setRulesOpen(true)}>
                <Settings2 className="h-4 w-4" /> Detection rules
              </button>
            )}
            <button
              type="button"
              className="btn-ghost"
              onClick={() => {
                setStatus("new");
                setSeverity("");
                setPage(1);
              }}
            >
              <Inbox className="h-4 w-4" /> New only
            </button>
          </>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard
          label="New alerts"
          value={counters?.new ?? "—"}
          hint="Awaiting first action"
          icon={<BellRing className="h-4 w-4" />}
          tone="rose"
          onClick={() => quickFilter({ status: "new" })}
        />
        <StatCard
          label="Unassigned"
          value={counters?.unassigned ?? "—"}
          hint="No analyst owner"
          icon={<UserRound className="h-4 w-4" />}
          tone="amber"
          onClick={() => quickFilter({ status: "" })}
        />
        <StatCard
          label="Assigned to me"
          value={counters?.mine ?? "—"}
          hint="Your active workload"
          icon={<ShieldAlert className="h-4 w-4" />}
          tone="cyan"
        />
        <StatCard
          label="Open"
          value={counters?.open ?? "—"}
          hint="Not resolved or closed"
          icon={<Filter className="h-4 w-4" />}
          tone="violet"
          onClick={() => quickFilter({ status: "" })}
        />
        <StatCard
          label="Last 24 hours"
          value={counters?.today ?? "—"}
          hint="Newly raised alerts"
          icon={<Sparkles className="h-4 w-4" />}
          tone="mint"
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.55fr_0.45fr]">
        <SectionCard
          title="Triage queue"
          subtitle={`${alerts.data?.meta.total ?? 0} alerts in your clearance`}
          action={
            <div className="flex items-center gap-2">
              {status && (
                <button type="button" className="chip border-cyan-400/25 bg-cyan-400/8 text-cyan-300" onClick={() => setStatus("")}>
                  {status} <span className="text-cyan-500">×</span>
                </button>
              )}
              {severity && (
                <button type="button" className="chip border-ink-600/60 bg-ink-800/50 text-slate-300" onClick={() => setSeverity("")}>
                  {severity} <span className="text-slate-500">×</span>
                </button>
              )}
            </div>
          }
          bodyClassName="p-0"
        >
          <div className="flex flex-col gap-2 border-b border-ink-600/40 p-3 sm:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search alert titles…"
                className="input h-9 py-1.5 pl-9 text-xs"
              />
            </div>
            <select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1); }} className="select h-9 py-1.5 text-xs sm:w-40">
              <option value="">All statuses</option>
              {STATUS_OPTIONS.map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </select>
            <select value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(1); }} className="select h-9 py-1.5 text-xs sm:w-36">
              <option value="">All severity</option>
              {SEVERITY_OPTIONS.map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </select>
          </div>

          {alerts.isLoading ? (
            <div className="p-4">
              <LoadingPanel rows={6} />
            </div>
          ) : alerts.isError ? (
            <div className="p-4">
              <ErrorPanel
                message={alerts.error instanceof ApiError ? alerts.error.message : "Alert queue unavailable"}
                retry={() => void alerts.refetch()}
              />
            </div>
          ) : queue.length === 0 ? (
            <EmptyState
              title="No alerts match the current filters"
              description="Try clearing the status or severity filter, or search a different title."
              icon={<CheckCircle2 className="h-5 w-5" />}
            />
          ) : (
            <>
              <div className="table-wrap rounded-none border-0">
                <table className="data-table min-w-[860px]">
                  <thead>
                    <tr>
                      <th>Alert</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Assignee</th>
                      <th>TLP</th>
                      <th>Age</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {queue.map((alert) => (
                      <tr key={alert.id} className="cursor-pointer" onClick={() => setSelectedAlert(alert.id)}>
                        <td>
                          <span className="block max-w-[320px] truncate text-xs font-medium text-slate-200">{alert.title}</span>
                          <span className="mt-0.5 block max-w-[320px] truncate text-[10px] text-slate-600">
                            {alert.indicator ? shortValue(alert.indicator.value, 46) : alert.rule ?? "Detection rule"}
                          </span>
                        </td>
                        <td><SeverityBadge severity={alert.severity} score={alert.score} /></td>
                        <td><StatusBadge status={alert.status} /></td>
                        <td className="text-xs text-slate-400">{alert.assignee?.name ?? <span className="text-slate-600">Unassigned</span>}</td>
                        <td><TlpBadge tlp={alert.tlp} /></td>
                        <td className="whitespace-nowrap text-xs text-slate-500">{relativeTime(alert.created_at)}</td>
                        <td><ArrowUpRight className="h-3.5 w-3.5 text-slate-600" /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination
                page={page}
                size={alerts.data?.meta.size ?? 20}
                total={alerts.data?.meta.total ?? 0}
                onChange={setPage}
              />
            </>
          )}
        </SectionCard>

        <SectionCard
          title="Recent indicators"
          subtitle="Newest intelligence in clearance"
          bodyClassName="p-0"
          action={
            has("search") ? (
              <button type="button" className="btn-ghost h-8 px-2 text-[10px]" onClick={() => navigate("/hunting")}>
                Hunt <ArrowUpRight className="h-3 w-3" />
              </button>
            ) : undefined
          }
        >
          <div className="divide-y divide-ink-700/40">
            {(dashboard.data?.data.recent_indicators ?? []).map((indicator) => (
              <button
                key={indicator.id}
                type="button"
                onClick={() => has("view_indicators") && setSelectedIndicator(indicator.id)}
                className="flex w-full items-center gap-3 px-4 py-2.5 text-left transition hover:bg-ink-800/50"
              >
                <span className={cn("h-7 w-0.5 rounded-full", indicator.severity === "critical" ? "bg-rose-400" : indicator.severity === "high" ? "bg-amber-300" : "bg-cyan-300")} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-[11px] text-slate-300">{shortValue(indicator.value, 38)}</span>
                  <span className="mt-0.5 block text-[10px] text-slate-600">
                    {indicator.type} · {relativeTime(indicator.last_seen)}
                  </span>
                </span>
                <span className="font-mono text-[11px] text-slate-400">{indicator.severity_score}</span>
              </button>
            ))}
            {!dashboard.data?.data.recent_indicators.length && (
              <p className="px-4 py-10 text-center text-xs text-slate-500">No recent indicators.</p>
            )}
          </div>
        </SectionCard>
      </div>

      <AlertDrawer
        alertId={selectedAlert}
        onClose={closeAlert}
        onOpenIndicator={(id) => {
          setSelectedIndicator(id);
          closeAlert();
        }}
      />
      {has("view_indicators") && (
        <IndicatorDrawer indicatorId={selectedIndicator} onClose={() => setSelectedIndicator(null)} />
      )}
      {has("manage_rules") && <RulesModal open={rulesOpen} onClose={() => setRulesOpen(false)} />}
    </div>
  );
}

function RulesModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const rules = useQuery({ queryKey: ["alert-rules"], queryFn: api.rules, enabled: open });
  const update = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.updateRule(id, { enabled }),
    onSuccess: () => {
      toast.success("Rule updated");
      void queryClient.invalidateQueries({ queryKey: ["alert-rules"] });
    },
    onError: (error) => toast.error("Could not update rule", error instanceof ApiError ? error.message : undefined),
  });

  return (
    <Modal open={open} onClose={onClose} title="Detection rules" description="Scoring thresholds and routing for automated alert creation." width="max-w-3xl">
      {rules.isLoading ? (
        <LoadingPanel rows={4} />
      ) : rules.isError ? (
        <ErrorPanel message="Detection rules could not be loaded" retry={() => void rules.refetch()} />
      ) : (
        <div className="space-y-2">
          {(rules.data?.data ?? []).map((rule) => (
            <div key={rule.id} className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-medium text-slate-200">{rule.name}</p>
                  <p className="mt-1 text-[11px] text-slate-500">
                    Minimum score {rule.min_score} · TLP max {rule.tlp_max} · {rule.types.length ? rule.types.join(", ") : "all types"}
                    {rule.categories.length ? ` · ${rule.categories.join(", ")}` : ""}
                  </p>
                  <p className="mt-0.5 text-[10px] text-slate-600">
                    Routes to {rule.route_roles.length ? rule.route_roles.join(", ") : "default analyst roles"}
                    {rule.route_user_ids.length ? ` + ${rule.route_user_ids.length} user(s)` : ""}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={cn("text-[10px]", rule.enabled ? "text-mint" : "text-slate-600")}>
                    {rule.enabled ? "Enabled" : "Paused"}
                  </span>
                  <Toggle
                    checked={rule.enabled}
                    onChange={(enabled) => update.mutate({ id: rule.id, enabled })}
                    label={`Toggle ${rule.name}`}
                    disabled={update.isPending}
                  />
                </div>
              </div>
            </div>
          ))}
          {!rules.data?.data.length && (
            <EmptyState title="No rules configured" description="Create detection rules through the API." icon={<Settings2 className="h-5 w-5" />} />
          )}
        </div>
      )}
    </Modal>
  );
}
