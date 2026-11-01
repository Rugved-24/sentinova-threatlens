import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  FileSearch,
  Fingerprint,
  Loader2,
  Lock,
  Search,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import {
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  Modal,
  PageHeader,
  Pagination,
  SectionCard,
} from "../components/ui";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import type { AuditEntry } from "../lib/types";
import { cn, formatDate, shortValue } from "../lib/utils";

export function Audit() {
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [selected, setSelected] = useState<AuditEntry | null>(null);

  const audit = useQuery({
    queryKey: ["audit", { page, action, actor }],
    queryFn: () => api.audit({ page, size: 50, action: action || undefined, actor: actor || undefined }),
  });

  const verify = useMutation({
    mutationFn: api.verifyAudit,
    onSuccess: (response) => {
      if (response.data.valid) toast.success("Audit chain verified", response.data.message);
      else toast.error("Audit chain integrity failure", response.data.message);
    },
    onError: (error) => toast.error("Verification failed", error instanceof ApiError ? error.message : undefined),
  });

  const rows = audit.data?.data ?? [];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Governance"
        title="Audit trail"
        description="Append-only, hash-chained record of security-relevant actions. Each entry commits to its predecessor, making silent edits detectable."
        actions={
          <button type="button" className="btn-primary" onClick={() => verify.mutate()} disabled={verify.isPending}>
            {verify.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            Verify chain
          </button>
        }
      />

      {verify.data && (
        <div
          className={cn(
            "flex items-start gap-3 rounded-2xl border px-4 py-3",
            verify.data.data.valid ? "border-mint/25 bg-mint/[0.045]" : "border-rose-400/25 bg-rose-500/[0.055]",
          )}
        >
          {verify.data.data.valid ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-mint" />
          ) : (
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-300" />
          )}
          <div>
            <p className={cn("text-xs font-medium", verify.data.data.valid ? "text-emerald-200" : "text-rose-200")}>
              {verify.data.data.message}
            </p>
            <p className="mt-0.5 text-[10px] text-slate-500">
              {verify.data.data.entries} entries verified
              {verify.data.data.head ? ` · head ${shortValue(verify.data.data.head, 24)}` : ""}
              {verify.data.data.broken_at ? ` · broken at entry ${verify.data.data.broken_at}` : ""}
            </p>
          </div>
        </div>
      )}

      <SectionCard title="Event ledger" subtitle={`${audit.data?.meta.total ?? 0} recorded actions`} bodyClassName="p-0">
        <div className="flex flex-col gap-2 border-b border-ink-600/40 p-3 sm:flex-row">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              value={action}
              onChange={(event) => { setAction(event.target.value); setPage(1); }}
              placeholder="Filter by action, e.g. auth.login or alert.update…"
              className="input h-9 py-1.5 pl-9 text-xs"
            />
          </div>
          <input
            value={actor}
            onChange={(event) => { setActor(event.target.value); setPage(1); }}
            placeholder="Actor email"
            className="input h-9 py-1.5 text-xs sm:w-56"
          />
        </div>

        {audit.isLoading ? (
          <div className="p-4"><LoadingPanel rows={8} /></div>
        ) : audit.isError ? (
          <div className="p-4">
            <ErrorPanel
              message={audit.error instanceof ApiError ? audit.error.message : "Audit ledger unavailable"}
              retry={() => void audit.refetch()}
            />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState title="No audit entries match" description="Adjust the action or actor filter." icon={<FileSearch className="h-5 w-5" />} />
        ) : (
          <>
            <div className="table-wrap rounded-none border-0">
              <table className="data-table min-w-[940px]">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Object</th>
                    <th>IP</th>
                    <th>Entry hash</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((entry) => (
                    <tr key={entry.id} className="cursor-pointer" onClick={() => setSelected(entry)}>
                      <td className="whitespace-nowrap text-xs text-slate-500">{formatDate(entry.ts)}</td>
                      <td className="text-xs text-slate-300">{entry.actor_email ?? <span className="text-slate-600">system</span>}</td>
                      <td>
                        <span className="chip border-ink-600/60 bg-ink-800/50 font-mono text-[10px] text-cyan-200">{entry.action}</span>
                      </td>
                      <td className="text-xs text-slate-500">
                        {entry.object_type ? `${entry.object_type}${entry.object_id ? ` · ${shortValue(entry.object_id, 10)}` : ""}` : "—"}
                      </td>
                      <td className="font-mono text-[10px] text-slate-500">{entry.ip ?? "—"}</td>
                      <td className="font-mono text-[10px] text-slate-600">{shortValue(entry.entry_hash, 20)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} size={audit.data?.meta.size ?? 50} total={audit.data?.meta.total ?? 0} onChange={setPage} />
          </>
        )}
      </SectionCard>

      <div className="flex items-start gap-2 rounded-xl border border-ink-600/50 bg-ink-850/40 px-4 py-3 text-[10px] leading-relaxed text-slate-500">
        <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-300" />
        Database triggers reject updates and deletes against the audit ledger. Hash chaining detects out-of-band tampering
        when the chain is verified.
      </div>

      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title="Audit entry"
        description={selected ? `Entry ${selected.id} · ${formatDate(selected.ts)}` : undefined}
        width="max-w-2xl"
      >
        {selected && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              {[
                ["Action", selected.action],
                ["Actor", selected.actor_email ?? "system"],
                ["Object", `${selected.object_type ?? "—"} ${selected.object_id ?? ""}`],
                ["IP", selected.ip ?? "—"],
                ["Correlation ID", selected.correlation_id ?? "—"],
                ["Entry hash", selected.entry_hash],
                ["Previous hash", selected.prev_hash],
              ].map(([label, value]) => (
                <div key={label} className="rounded-xl border border-ink-600/50 bg-ink-850/40 px-3 py-2">
                  <p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">{label}</p>
                  <p className="mt-1 break-all font-mono text-[10px] text-slate-300">{value}</p>
                </div>
              ))}
            </div>
            <div className="rounded-xl border border-ink-600/50 bg-ink-950/50 p-3">
              <p className="mb-2 flex items-center gap-1.5 text-[9px] uppercase tracking-[0.14em] text-slate-600">
                <Fingerprint className="h-3 w-3" /> Detail
              </p>
              <pre className="max-h-64 overflow-auto text-[10px] leading-relaxed text-slate-400">
                {JSON.stringify(selected.detail, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
