import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  CheckCircle2,
  CircleDot,
  Clock3,
  Loader2,
  Siren,
  UserRoundCheck,
} from "lucide-react";
import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import type { Alert } from "../lib/types";
import { formatDate, relativeTime, shortValue } from "../lib/utils";
import { Drawer, ErrorPanel, LoadingPanel, SeverityBadge, StatusBadge, TlpBadge } from "./ui";

const NEXT_ACTIONS: Record<Alert["status"], Array<{ value: Alert["status"]; label: string }>> = {
  new: [
    { value: "acknowledged", label: "Acknowledge" },
    { value: "in-progress", label: "Start investigation" },
    { value: "resolved", label: "Resolve" },
  ],
  acknowledged: [
    { value: "in-progress", label: "Start investigation" },
    { value: "resolved", label: "Resolve" },
  ],
  "in-progress": [{ value: "resolved", label: "Resolve" }],
  resolved: [{ value: "closed", label: "Close" }],
  closed: [],
};

export function AlertDrawer({
  alertId,
  onClose,
  onOpenIndicator,
}: {
  alertId: string | null;
  onClose: () => void;
  onOpenIndicator: (id: string) => void;
}) {
  const { user, has } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [escalating, setEscalating] = useState(false);
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentSummary, setIncidentSummary] = useState("");

  const query = useQuery({
    queryKey: ["alert", alertId],
    queryFn: () => api.alert(alertId as string),
    enabled: Boolean(alertId),
  });
  const alert = query.data?.data;

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["alert", alertId] });
    void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    void queryClient.invalidateQueries({ queryKey: ["analyst"] });
    void queryClient.invalidateQueries({ queryKey: ["executive"] });
    void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    void queryClient.invalidateQueries({ queryKey: ["badges"] });
  };

  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.updateAlert(alertId as string, body),
    onSuccess: () => {
      toast.success("Alert updated");
      invalidate();
    },
    onError: (error) => toast.error("Could not update alert", error instanceof ApiError ? error.message : undefined),
  });

  const escalate = useMutation({
    mutationFn: () =>
      api.escalateAlert(alertId as string, {
        title: incidentTitle.trim() || undefined,
        summary: incidentSummary.trim() || undefined,
      }),
    onSuccess: (response) => {
      toast.success("Incident opened", response.data.title);
      setEscalating(false);
      setIncidentTitle("");
      setIncidentSummary("");
      invalidate();
      void queryClient.invalidateQueries({ queryKey: ["incident", response.data.id] });
    },
    onError: (error) => toast.error("Escalation failed", error instanceof ApiError ? error.message : undefined),
  });

  return (
    <Drawer
      open={Boolean(alertId)}
      onClose={onClose}
      title={alert ? alert.title : "Alert detail"}
      subtitle={
        alert ? (
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] text-slate-600">#{alert.id.slice(0, 8)}</span>
            <span className="text-slate-700">·</span>
            <span>raised {relativeTime(alert.created_at)}</span>
          </span>
        ) : undefined
      }
    >
      {query.isLoading ? (
        <LoadingPanel rows={6} />
      ) : query.isError || !alert ? (
        <ErrorPanel
          message={query.error instanceof ApiError ? query.error.message : "Alert could not be loaded"}
          retry={() => void query.refetch()}
        />
      ) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} score={alert.score} />
            <TlpBadge tlp={alert.tlp} />
            <StatusBadge status={alert.status} />
            {alert.rule && (
              <span className="chip border-ink-600/60 bg-ink-800/50 text-[10px] text-slate-400">
                rule · {alert.rule}
              </span>
            )}
          </div>

          <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
            <p className="label mb-2">Detection summary</p>
            <p className="text-sm leading-relaxed text-slate-300">{alert.description || "No description supplied."}</p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-xl border border-ink-600/50 bg-ink-850/40 px-3 py-2.5">
              <p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">Assignee</p>
              <p className="mt-1 text-xs text-slate-200">{alert.assignee?.name ?? "Unassigned"}</p>
            </div>
            <div className="rounded-xl border border-ink-600/50 bg-ink-850/40 px-3 py-2.5">
              <p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">Created</p>
              <p className="mt-1 text-xs text-slate-200">{formatDate(alert.created_at)}</p>
            </div>
            <div className="rounded-xl border border-ink-600/50 bg-ink-850/40 px-3 py-2.5">
              <p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">Acknowledged</p>
              <p className="mt-1 text-xs text-slate-200">{alert.acknowledged_at ? relativeTime(alert.acknowledged_at) : "—"}</p>
            </div>
            <div className="rounded-xl border border-ink-600/50 bg-ink-850/40 px-3 py-2.5">
              <p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">Incident</p>
              <p className="mt-1 truncate text-xs text-slate-200">{alert.incident?.title ?? "Not escalated"}</p>
            </div>
          </div>

          {alert.indicator && (
            <div className="rounded-2xl border border-cyan-400/15 bg-cyan-400/[0.035] p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="label mb-1">Linked indicator</p>
                  <p className="truncate font-mono text-xs text-cyan-100">{shortValue(alert.indicator.value, 64)}</p>
                  <p className="mt-1 text-[10px] text-slate-500">
                    {alert.indicator.type} · score {alert.indicator.severity_score} · {alert.indicator.internal_sightings} internal sightings
                  </p>
                </div>
                <button
                  type="button"
                  className="btn-ghost h-8 shrink-0 px-2 text-[11px]"
                  onClick={() => onOpenIndicator(alert.indicator!.id)}
                >
                  Inspect <ArrowUpRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}

          {has("manage_alerts") && (
            <div className="space-y-3">
              <div>
                <p className="label mb-2">Workflow</p>
                <div className="flex flex-wrap gap-2">
                  {NEXT_ACTIONS[alert.status].map((action) => (
                    <button
                      key={action.value}
                      type="button"
                      className={action.value === "resolved" || action.value === "closed" ? "btn-ghost" : "btn-primary"}
                      disabled={update.isPending}
                      onClick={() => update.mutate({ status: action.value })}
                    >
                      {action.value === "resolved" || action.value === "closed" ? (
                        <CheckCircle2 className="h-4 w-4" />
                      ) : (
                        <Clock3 className="h-4 w-4" />
                      )}
                      {action.label}
                    </button>
                  ))}
                  {alert.status === "new" && (
                    <button
                      type="button"
                      className="btn-ghost"
                      disabled={update.isPending}
                      onClick={() => update.mutate({ status: "acknowledged", assignee_id: user?.id })}
                    >
                      <UserRoundCheck className="h-4 w-4" /> Acknowledge &amp; assign me
                    </button>
                  )}
                  {!alert.assignee && alert.status !== "closed" && (
                    <button
                      type="button"
                      className="btn-ghost"
                      disabled={update.isPending}
                      onClick={() => update.mutate({ assignee_id: user?.id })}
                    >
                      <UserRoundCheck className="h-4 w-4" /> Assign to me
                    </button>
                  )}
                </div>
              </div>

              {alert.status !== "closed" && !alert.incident && (
                <div className="rounded-2xl border border-rose-400/20 bg-rose-500/[0.035] p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-medium text-rose-200">Escalate to incident</p>
                      <p className="mt-0.5 text-[11px] text-slate-500">Open a coordinated response case with a timeline.</p>
                    </div>
                    <button type="button" className="btn-danger h-8 px-2.5 text-[11px]" onClick={() => setEscalating((value) => !value)}>
                      <Siren className="h-3.5 w-3.5" /> {escalating ? "Cancel" : "Escalate"}
                    </button>
                  </div>
                  {escalating && (
                    <form
                      className="mt-3 space-y-2"
                      onSubmit={(event) => {
                        event.preventDefault();
                        escalate.mutate();
                      }}
                    >
                      <input
                        value={incidentTitle}
                        onChange={(event) => setIncidentTitle(event.target.value)}
                        className="input h-9 py-1.5 text-xs"
                        placeholder={`Incident: ${alert.title}`}
                      />
                      <textarea
                        value={incidentSummary}
                        onChange={(event) => setIncidentSummary(event.target.value)}
                        className="input resize-none text-xs"
                        rows={2}
                        placeholder="Response summary and initial scope…"
                      />
                      <button type="submit" className="btn-danger w-full" disabled={escalate.isPending}>
                        {escalate.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Siren className="h-4 w-4" />}
                        Open incident
                      </button>
                    </form>
                  )}
                </div>
              )}
            </div>
          )}

          <div className="flex items-center gap-2 rounded-xl border border-ink-600/40 bg-ink-900/40 px-3 py-2 text-[10px] text-slate-600">
            <CircleDot className="h-3 w-3 text-cyan-400/60" />
            Every status change and assignment is appended to the audit chain.
          </div>
        </div>
      )}
    </Drawer>
  );
}
