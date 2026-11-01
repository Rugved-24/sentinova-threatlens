import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CalendarDays,
  Download,
  FileText,
  Loader2,
  Plus,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { useState } from "react";
import {
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  Modal,
  PageHeader,
  SectionCard,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import type { Report } from "../lib/types";
import { cn, formatDate } from "../lib/utils";

type ReportKind = "executive" | "operational" | "incident";

const KIND_META: Record<ReportKind, { label: string; description: string; tone: string }> = {
  executive: {
    label: "Executive",
    description: "Risk posture, trend and priority indicators for leadership.",
    tone: "border-cyan-400/20 bg-cyan-400/8 text-cyan-200",
  },
  operational: {
    label: "Operational",
    description: "Indicator corpus, source coverage and ATT&CK observations.",
    tone: "border-violet/20 bg-violet/8 text-violet-200",
  },
  incident: {
    label: "Incident",
    description: "Case timeline, linked alerts and containment status.",
    tone: "border-amber-400/20 bg-amber-400/8 text-amber-200",
  },
};

export function Reports() {
  const { has } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);

  const reports = useQuery({ queryKey: ["reports"], queryFn: api.reports, refetchInterval: 60_000 });

  const download = async (report: Report) => {
    setDownloading(report.id);
    try {
      await api.downloadReport(report.id, report.title);
      toast.success("Download started", report.title);
    } catch (error) {
      toast.error("Download failed", error instanceof ApiError ? error.message : undefined);
    } finally {
      setDownloading(null);
    }
  };

  const rows = reports.data?.data ?? [];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Intelligence products"
        title="Reports"
        description="Generate shareable PDF intelligence briefs. Report access is scoped to the requester and audited on download."
        actions={
          has("generate_reports") ? (
            <button type="button" className="btn-primary" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" /> Generate report
            </button>
          ) : undefined
        }
      />

      <div className="grid gap-4 md:grid-cols-3">
        {Object.entries(KIND_META).map(([kind, meta]) => (
          <div key={kind} className="panel p-4">
            <span className={cn("chip text-[10px]", meta.tone)}>
              <FileText className="h-3 w-3" /> {meta.label}
            </span>
            <p className="mt-3 text-xs leading-relaxed text-slate-500">{meta.description}</p>
            <p className="mt-2 font-mono text-[10px] text-slate-600">
              {rows.filter((report) => report.kind === kind).length} generated
            </p>
          </div>
        ))}
      </div>

      <SectionCard title="Report library" subtitle="PDF products generated from the current corpus" bodyClassName="p-0">
        {reports.isLoading ? (
          <div className="p-4"><LoadingPanel rows={5} /></div>
        ) : reports.isError ? (
          <div className="p-4">
            <ErrorPanel
              message={reports.error instanceof ApiError ? reports.error.message : "Reports could not be loaded"}
              retry={() => void reports.refetch()}
            />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No reports generated"
            description="Create an executive, operational or incident brief. The PDF is generated locally and stored securely."
            icon={<FileText className="h-5 w-5" />}
            action={
              <button type="button" className="btn-primary" onClick={() => setCreateOpen(true)}>
                <Sparkles className="h-4 w-4" /> Generate first report
              </button>
            }
          />
        ) : (
          <div className="table-wrap rounded-none border-0">
            <table className="data-table min-w-[760px]">
              <thead>
                <tr>
                  <th>Report</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Completed</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((report) => {
                  const meta = KIND_META[(report.kind as ReportKind) in KIND_META ? (report.kind as ReportKind) : "operational"];
                  return (
                    <tr key={report.id}>
                      <td>
                        <p className="max-w-[360px] truncate text-xs font-medium text-slate-200">{report.title}</p>
                        <p className="mt-0.5 font-mono text-[10px] text-slate-600">#{report.id.slice(0, 8)}</p>
                      </td>
                      <td>
                        <span className={cn("chip text-[10px]", meta.tone)}>{meta.label}</span>
                      </td>
                      <td>
                        <span
                          className={cn(
                            "chip text-[10px] capitalize",
                            report.status === "ready"
                              ? "border-mint/25 bg-mint/8 text-emerald-300"
                              : report.status === "failed"
                                ? "border-rose-400/25 bg-rose-500/8 text-rose-300"
                                : "border-amber-400/25 bg-amber-400/8 text-amber-300",
                          )}
                        >
                          {report.status}
                        </span>
                      </td>
                      <td className="whitespace-nowrap text-xs text-slate-500">{formatDate(report.created_at)}</td>
                      <td className="whitespace-nowrap text-xs text-slate-500">
                        {report.completed_at ? formatDate(report.completed_at) : "—"}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn-ghost h-8 px-2 text-[10px]"
                          disabled={!report.download_url || downloading === report.id}
                          onClick={() => void download(report)}
                        >
                          {downloading === report.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
                          PDF
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <div className="flex items-start gap-2 rounded-xl border border-ink-600/50 bg-ink-850/40 px-4 py-3 text-[10px] leading-relaxed text-slate-500">
        <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-mint" />
        Reports are generated from synthetic demonstration data. PDFs are written to the configured reports directory with
        path traversal protection and every download is appended to the audit chain.
      </div>

      {has("generate_reports") && (
        <CreateReportModal
          open={createOpen}
          onClose={() => setCreateOpen(false)}
          onCreated={() => void queryClient.invalidateQueries({ queryKey: ["reports"] })}
          canSelectIncident={has("read_incidents")}
        />
      )}
    </div>
  );
}

function CreateReportModal({
  open,
  onClose,
  onCreated,
  canSelectIncident,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
  canSelectIncident: boolean;
}) {
  const toast = useToast();
  const [kind, setKind] = useState<ReportKind>("executive");
  const [title, setTitle] = useState("");
  const [incidentId, setIncidentId] = useState("");

  const incidents = useQuery({
    queryKey: ["incidents", "report-options"],
    queryFn: () => api.incidents({ size: 100 }),
    enabled: open && canSelectIncident,
  });

  const create = useMutation({
    mutationFn: () =>
      api.createReport({
        kind,
        title: title.trim() || `${KIND_META[kind].label} Threat Report`,
        incident_id: kind === "incident" ? incidentId : undefined,
      }),
    onSuccess: async (response) => {
      toast.success("Report generated", response.data.title);
      onCreated();
      onClose();
      setTitle("");
      if (response.data.download_url) {
        await api.downloadReport(response.data.id, response.data.title).catch(() =>
          toast.error("Report generated, but the download failed"),
        );
      }
    },
    onError: (error) => toast.error("Report generation failed", error instanceof ApiError ? error.message : undefined),
  });

  return (
    <Modal open={open} onClose={onClose} title="Generate intelligence report" description="Build a PDF from the current cleared corpus.">
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (kind !== "incident" || incidentId) create.mutate();
        }}
      >
        <div>
          <label className="label mb-1.5 block">Report type</label>
          <div className="grid gap-2 sm:grid-cols-3">
            {(Object.keys(KIND_META) as ReportKind[]).map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => setKind(item)}
                disabled={item === "incident" && !canSelectIncident}
                className={cn(
                  "rounded-xl border px-3 py-2.5 text-left transition disabled:cursor-not-allowed disabled:opacity-40",
                  kind === item ? "border-cyan-400/40 bg-cyan-400/8" : "border-ink-600/60 bg-ink-850/40 hover:border-ink-600",
                )}
              >
                <span className="block text-xs font-medium text-slate-200">{KIND_META[item].label}</span>
                <span className="mt-0.5 block text-[9px] leading-relaxed text-slate-600">{KIND_META[item].description}</span>
              </button>
            ))}
          </div>
        </div>
        <div>
          <label className="label mb-1.5 block">Title</label>
          <input value={title} onChange={(event) => setTitle(event.target.value)} className="input" placeholder={`${KIND_META[kind].label} Threat Report · ${new Date().toLocaleDateString()}`} />
        </div>
        {kind === "incident" && (
          <div>
            <label className="label mb-1.5 block">Incident</label>
            <select value={incidentId} onChange={(event) => setIncidentId(event.target.value)} className="select" required>
              <option value="">Select an incident…</option>
              {(incidents.data?.data ?? []).map((incident) => (
                <option key={incident.id} value={incident.id}>{incident.title}</option>
              ))}
            </select>
          </div>
        )}
        <div className="flex items-center gap-2 rounded-xl border border-ink-600/50 bg-ink-900/50 px-3 py-2 text-[10px] text-slate-500">
          <CalendarDays className="h-3.5 w-3.5 text-cyan-300" />
          The report reflects data at generation time and includes a handling caveat.
        </div>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={create.isPending || (kind === "incident" && !incidentId)}>
            {create.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Generate PDF
          </button>
        </div>
      </form>
    </Modal>
  );
}
