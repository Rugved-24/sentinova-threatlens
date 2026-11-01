import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  CheckSquare,
  Circle,
  ClipboardList,
  Clock3,
  Loader2,
  MessageSquarePlus,
  Plus,
  Search,
  Swords,
  UserRound,
} from "lucide-react";
import { useEffect, useState } from "react";
import { IndicatorDrawer } from "../components/IndicatorDrawer";
import {
  Drawer,
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  Modal,
  PageHeader,
  SectionCard,
  SeverityBadge,
  StatusBadge,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { subscribeTopic, unsubscribeTopic } from "../hooks/useWebSocket";
import { api, ApiError } from "../lib/api";
import type { Incident, Severity } from "../lib/types";
import { cn, formatDate, relativeTime, shortValue } from "../lib/utils";

const STATUSES: Incident["status"][] = ["open", "investigating", "contained", "closed"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export function Incidents() {
  const { has } = useAuth();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedIndicator, setSelectedIndicator] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

  useEffect(() => {
    if (!selected) return;
    const topic = `incidents.${selected}`;
    subscribeTopic(topic);
    return () => unsubscribeTopic(topic);
  }, [selected]);

  const incidents = useQuery({
    queryKey: ["incidents", { status, q: query }],
    queryFn: () => api.incidents({ status: status || undefined, q: query || undefined, size: 100 }),
    refetchInterval: 45_000,
  });

  const rows = incidents.data?.data ?? [];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Incident response"
        title="Response cases"
        description="Coordinate investigation, containment and closure. Timeline entries are append-only and every change is recorded."
        actions={
          has("manage_incidents") ? (
            <button type="button" className="btn-primary" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" /> New incident
            </button>
          ) : undefined
        }
      />

      <SectionCard
        title="Incident register"
        subtitle={`${incidents.data?.meta.total ?? 0} cases`}
        bodyClassName="p-0"
      >
        <div className="flex flex-col gap-2 border-b border-ink-600/40 p-3 sm:flex-row">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search incidents…"
              className="input h-9 py-1.5 pl-9 text-xs"
            />
          </div>
          <select value={status} onChange={(event) => setStatus(event.target.value)} className="select h-9 py-1.5 text-xs sm:w-44">
            <option value="">All statuses</option>
            {STATUSES.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
        </div>

        {incidents.isLoading ? (
          <div className="p-4"><LoadingPanel rows={5} /></div>
        ) : incidents.isError ? (
          <div className="p-4">
            <ErrorPanel
              message={incidents.error instanceof ApiError ? incidents.error.message : "Incidents could not be loaded"}
              retry={() => void incidents.refetch()}
            />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No incidents found"
            description="Escalate a high-confidence alert or create a case directly to begin response coordination."
            icon={<Swords className="h-5 w-5" />}
          />
        ) : (
          <div className="grid gap-3 p-3 md:grid-cols-2 xl:grid-cols-3">
            {rows.map((incident) => (
              <button
                key={incident.id}
                type="button"
                onClick={() => setSelected(incident.id)}
                className="panel panel-hover flex flex-col gap-3 p-4 text-left"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-100">{incident.title}</p>
                    <p className="mt-1 text-[10px] text-slate-600">#{incident.id.slice(0, 8)} · opened {relativeTime(incident.created_at)}</p>
                  </div>
                  <ArrowUpRight className="h-4 w-4 shrink-0 text-slate-600" />
                </div>
                <p className="line-clamp-2 text-[11px] leading-relaxed text-slate-500">{incident.summary || "No summary yet."}</p>
                <div className="flex flex-wrap items-center gap-1.5">
                  <SeverityBadge severity={incident.severity} />
                  <StatusBadge status={incident.status} />
                  <span className="chip border-ink-600/50 bg-ink-800/50 text-[10px] text-slate-500">
                    {incident.alert_count} alerts
                  </span>
                  <span className="chip border-ink-600/50 bg-ink-800/50 text-[10px] text-slate-500">
                    {incident.indicator_count} indicators
                  </span>
                </div>
                <div>
                  <div className="mb-1 flex items-center justify-between text-[10px] text-slate-500">
                    <span className="flex items-center gap-1"><ClipboardList className="h-3 w-3" /> Checklist</span>
                    <span className="font-mono">{incident.checklist_done}/{incident.checklist_total}</span>
                  </div>
                  <div className="h-1 overflow-hidden rounded-full bg-ink-700/70">
                    <div
                      className="h-full rounded-full bg-cyan-400/70"
                      style={{ width: `${incident.checklist_total ? (incident.checklist_done / incident.checklist_total) * 100 : 0}%` }}
                    />
                  </div>
                </div>
                <div className="flex items-center justify-between border-t border-ink-700/40 pt-2 text-[10px] text-slate-600">
                  <span className="flex items-center gap-1"><UserRound className="h-3 w-3" /> {incident.owner?.name ?? "Unassigned"}</span>
                  <span className="flex items-center gap-1"><Clock3 className="h-3 w-3" /> {relativeTime(incident.updated_at)}</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </SectionCard>

      <IncidentDrawer
        incidentId={selected}
        onClose={() => setSelected(null)}
        onOpenIndicator={(id) => setSelectedIndicator(id)}
      />
      {has("view_indicators") && (
        <IndicatorDrawer indicatorId={selectedIndicator} onClose={() => setSelectedIndicator(null)} />
      )}
      {has("manage_incidents") && <CreateIncidentModal open={createOpen} onClose={() => setCreateOpen(false)} />}
    </div>
  );
}

function IncidentDrawer({
  incidentId,
  onClose,
  onOpenIndicator,
}: {
  incidentId: string | null;
  onClose: () => void;
  onOpenIndicator: (id: string) => void;
}) {
  const { has } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [note, setNote] = useState("");

  const query = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => api.incident(incidentId as string),
    enabled: Boolean(incidentId),
  });
  const incident = query.data?.data;

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
    void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    void queryClient.invalidateQueries({ queryKey: ["executive"] });
  };

  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.updateIncident(incidentId as string, body),
    onSuccess: () => {
      toast.success("Incident updated");
      invalidate();
    },
    onError: (error) => toast.error("Update failed", error instanceof ApiError ? error.message : undefined),
  });

  const addNote = useMutation({
    mutationFn: () => api.addTimeline(incidentId as string, { event_type: "note", message: note.trim() }),
    onSuccess: () => {
      setNote("");
      toast.success("Timeline note added");
      invalidate();
    },
    onError: (error) => toast.error("Could not add note", error instanceof ApiError ? error.message : undefined),
  });

  const toggleChecklist = (itemId: string) => {
    if (!incident) return;
    update.mutate({
      checklist: incident.checklist.map((item) => (item.id === itemId ? { ...item, done: !item.done } : item)),
    });
  };

  return (
    <Drawer
      open={Boolean(incidentId)}
      onClose={onClose}
      width="max-w-4xl"
      title={incident ? incident.title : "Incident detail"}
      subtitle={
        incident ? (
          <span className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-slate-600">#{incident.id.slice(0, 8)}</span>
            <span className="text-slate-700">·</span>
            <span>opened {formatDate(incident.created_at)}</span>
          </span>
        ) : undefined
      }
    >
      {query.isLoading ? (
        <LoadingPanel rows={8} />
      ) : query.isError || !incident ? (
        <ErrorPanel
          message={query.error instanceof ApiError ? query.error.message : "Incident could not be loaded"}
          retry={() => void query.refetch()}
        />
      ) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            <span className="chip border-ink-600/50 bg-ink-800/50 text-[10px] text-slate-400">
              owner · {incident.owner?.name ?? "unassigned"}
            </span>
          </div>

          <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
            <p className="label mb-2">Summary</p>
            <p className="text-sm leading-relaxed text-slate-300">{incident.summary || "No summary recorded."}</p>
          </div>

          {has("manage_incidents") && (
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="label mb-1.5 block">Status</label>
                <select
                  className="select"
                  value={incident.status}
                  onChange={(event) => update.mutate({ status: event.target.value })}
                >
                  {STATUSES.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </div>
              <div>
                <label className="label mb-1.5 block">Severity</label>
                <select
                  className="select"
                  value={incident.severity}
                  onChange={(event) => update.mutate({ severity: event.target.value })}
                >
                  {SEVERITIES.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </div>
            </div>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
              <div className="mb-3 flex items-center justify-between">
                <p className="label">Response checklist</p>
                <span className="font-mono text-[10px] text-slate-500">
                  {incident.checklist.filter((item) => item.done).length}/{incident.checklist.length}
                </span>
              </div>
              <div className="space-y-1.5">
                {incident.checklist.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    disabled={!has("manage_incidents") || update.isPending}
                    onClick={() => toggleChecklist(item.id)}
                    className="flex w-full items-start gap-2.5 rounded-lg px-2 py-1.5 text-left transition hover:bg-ink-800/50 disabled:cursor-default"
                  >
                    {item.done ? (
                      <CheckSquare className="mt-0.5 h-3.5 w-3.5 shrink-0 text-mint" />
                    ) : (
                      <Circle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-600" />
                    )}
                    <span className={cn("text-[11px] leading-relaxed", item.done ? "text-slate-500 line-through" : "text-slate-300")}>
                      {item.label}
                    </span>
                  </button>
                ))}
                {!incident.checklist.length && <p className="py-4 text-center text-[11px] text-slate-600">No checklist items.</p>}
              </div>
            </div>

            <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
              <p className="label mb-3">Linked intelligence</p>
              <div className="space-y-2">
                {(incident.alerts ?? []).slice(0, 5).map((alert) => (
                  <div key={alert.id} className="flex items-center gap-2 rounded-lg border border-ink-600/40 px-2.5 py-2">
                    <SeverityBadge severity={alert.severity} score={alert.score} />
                    <span className="min-w-0 flex-1 truncate text-[11px] text-slate-300">{alert.title}</span>
                    <StatusBadge status={alert.status} />
                  </div>
                ))}
                {(incident.indicators ?? []).slice(0, 5).map((indicator) => (
                  <button
                    key={indicator.id}
                    type="button"
                    onClick={() => onOpenIndicator(indicator.id)}
                    className="flex w-full items-center gap-2 rounded-lg border border-ink-600/40 px-2.5 py-2 text-left transition hover:border-cyan-400/25"
                  >
                    <SeverityBadge severity={indicator.severity} score={indicator.severity_score} />
                    <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-slate-300">{shortValue(indicator.value, 42)}</span>
                    <ArrowUpRight className="h-3 w-3 text-slate-600" />
                  </button>
                ))}
                {!incident.alerts?.length && !incident.indicators?.length && (
                  <p className="py-4 text-center text-[11px] text-slate-600">No linked alerts or indicators.</p>
                )}
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
            <p className="label mb-3">Timeline</p>
            <div className="max-h-[360px] space-y-0 overflow-y-auto pr-1">
              {(incident.timeline ?? []).map((entry, index) => (
                <div key={entry.id} className="relative flex gap-3 pb-4">
                  {index < (incident.timeline?.length ?? 0) - 1 && (
                    <span className="absolute left-[5px] top-3 h-full w-px bg-ink-600/50" />
                  )}
                  <span className="relative mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full border border-cyan-400/50 bg-ink-900">
                    <span className="absolute inset-0.5 rounded-full bg-cyan-400/70" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-start justify-between gap-3">
                      <p className="text-[11px] leading-relaxed text-slate-300">{entry.message}</p>
                      <span className="shrink-0 text-[9px] text-slate-600">{relativeTime(entry.created_at)}</span>
                    </div>
                    <p className="mt-0.5 text-[9px] uppercase tracking-[0.12em] text-slate-600">{entry.event_type}</p>
                  </div>
                </div>
              ))}
              {!incident.timeline?.length && <p className="py-4 text-center text-[11px] text-slate-600">Timeline is empty.</p>}
            </div>
            {has("manage_incidents") && (
              <form
                className="mt-2 flex gap-2 border-t border-ink-600/40 pt-3"
                onSubmit={(event) => {
                  event.preventDefault();
                  if (note.trim()) addNote.mutate();
                }}
              >
                <input
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  className="input h-9 py-1.5 text-xs"
                  placeholder="Add an investigation note…"
                />
                <button type="submit" className="btn-primary h-9 px-3" disabled={addNote.isPending || !note.trim()}>
                  {addNote.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <MessageSquarePlus className="h-3.5 w-3.5" />}
                </button>
              </form>
            )}
          </div>
        </div>
      )}
    </Drawer>
  );
}

function CreateIncidentModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [severity, setSeverity] = useState<Severity>("high");

  const create = useMutation({
    mutationFn: () => api.createIncident({ title: title.trim(), summary: summary.trim(), severity, status: "open" }),
    onSuccess: () => {
      toast.success("Incident created");
      setTitle("");
      setSummary("");
      setSeverity("high");
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["executive"] });
      onClose();
    },
    onError: (error) => toast.error("Could not create incident", error instanceof ApiError ? error.message : undefined),
  });

  return (
    <Modal open={open} onClose={onClose} title="Open a response case" description="Create an incident to coordinate containment and evidence.">
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (title.trim().length >= 3) create.mutate();
        }}
      >
        <div>
          <label className="label mb-1.5 block">Title</label>
          <input value={title} onChange={(event) => setTitle(event.target.value)} className="input" placeholder="Suspected C2 beaconing on finance subnet" required minLength={3} />
        </div>
        <div>
          <label className="label mb-1.5 block">Summary</label>
          <textarea value={summary} onChange={(event) => setSummary(event.target.value)} className="input resize-none" rows={4} placeholder="Initial scope, evidence and response hypothesis…" />
        </div>
        <div>
          <label className="label mb-1.5 block">Severity</label>
          <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity)} className="select">
            {SEVERITIES.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={create.isPending}>
            {create.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Create incident
          </button>
        </div>
      </form>
    </Modal>
  );
}
