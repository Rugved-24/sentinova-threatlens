import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  Clock3,
  FileUp,
  KeyRound,
  Loader2,
  Plus,
  RefreshCw,
  Rss,
  ShieldCheck,
  Timer,
  WifiOff,
} from "lucide-react";
import { useState } from "react";
import {
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  Modal,
  PageHeader,
  SectionCard,
  StatCard,
  Toggle,
} from "../components/ui";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import type { Feed } from "../lib/types";
import { cn, relativeTime } from "../lib/utils";

const KIND_LABEL: Record<string, string> = {
  demo: "Demo corpus",
  kev: "CISA KEV",
  urlhaus: "URLhaus",
  openphish: "OpenPhish",
  feodo: "Feodo Tracker",
  blocklistde: "Blocklist.de",
  et_compromised: "ET Compromised",
  cins: "CINS Army",
  phishing_army: "Phishing Army",
  otx: "AlienVault OTX",
  abuseipdb: "AbuseIPDB",
  threatfox: "ThreatFox",
  taxii: "TAXII 2.1",
};

export function Feeds() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [running, setRunning] = useState<string | null>(null);

  const feeds = useQuery({ queryKey: ["feeds"], queryFn: api.feeds, refetchInterval: 30_000 });
  const meta = useQuery({ queryKey: ["feed-meta"], queryFn: api.feedMeta });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => api.updateFeed(id, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
    onError: (error) => toast.error("Could not update feed", error instanceof ApiError ? error.message : undefined),
  });

  const run = useMutation({
    mutationFn: (id: string) => api.runFeed(id),
    onMutate: (id) => setRunning(id),
    onSuccess: () => {
      toast.success("Feed run queued", "Collection will complete in the background.");
      window.setTimeout(() => void queryClient.invalidateQueries({ queryKey: ["feeds"] }), 2200);
    },
    onError: (error) => toast.error("Feed run failed", error instanceof ApiError ? error.message : undefined),
    onSettled: () => setRunning(null),
  });

  const rows = feeds.data?.data ?? [];
  const enabled = rows.filter((feed) => feed.enabled).length;
  const healthy = rows.filter((feed) => feed.last_status === "ok").length;
  const totalIndicators = rows.reduce((sum, feed) => sum + feed.indicator_count, 0);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Collection fabric"
        title="Feeds & sources"
        description="Manage public and authenticated intelligence connectors. Secrets are encrypted at rest and never returned by the API."
        actions={
          <div className="flex gap-2">
            <button type="button" className="btn-ghost" onClick={() => setImportOpen(true)}>
              <FileUp className="h-4 w-4" /> Import CSV
            </button>
            <button type="button" className="btn-primary" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" /> Add feed
            </button>
          </div>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Configured feeds" value={rows.length} hint={`${enabled} enabled`} icon={<Rss className="h-4 w-4" />} />
        <StatCard label="Healthy" value={healthy} hint="Last run succeeded" icon={<CheckCircle2 className="h-4 w-4" />} tone="mint" />
        <StatCard
          label="Observed indicators"
          value={totalIndicators}
          hint="Distinct per source"
          icon={<ShieldCheck className="h-4 w-4" />}
          tone="violet"
        />
        <StatCard
          label="Needs attention"
          value={rows.filter((feed) => feed.last_status === "error").length}
          hint="Check connector errors"
          icon={<AlertCircle className="h-4 w-4" />}
          tone="rose"
        />
      </div>

      <SectionCard title="Connectors" subtitle="Polling schedules, health and collection volume" bodyClassName="p-0">
        {feeds.isLoading ? (
          <div className="p-4"><LoadingPanel rows={8} /></div>
        ) : feeds.isError ? (
          <div className="p-4">
            <ErrorPanel
              message={feeds.error instanceof ApiError ? feeds.error.message : "Feeds could not be loaded"}
              retry={() => void feeds.refetch()}
            />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState title="No feeds configured" description="Add a public or authenticated source to begin collection." icon={<WifiOff className="h-5 w-5" />} />
        ) : (
          <div className="table-wrap rounded-none border-0">
            <table className="data-table min-w-[980px]">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Status</th>
                  <th>Last run</th>
                  <th>Schedule</th>
                  <th>Indicators</th>
                  <th>Enabled</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((feed) => (
                  <tr key={feed.id}>
                    <td>
                      <div className="flex items-center gap-2.5">
                        <div className={cn("rounded-lg border p-1.5", feed.enabled ? "border-cyan-400/20 bg-cyan-400/8 text-cyan-300" : "border-ink-600/60 bg-ink-800/50 text-slate-600")}>
                          <Rss className="h-3.5 w-3.5" />
                        </div>
                        <div>
                          <p className="text-xs font-medium text-slate-200">{feed.name}</p>
                          <p className="mt-0.5 flex items-center gap-1.5 text-[10px] text-slate-600">
                            {KIND_LABEL[feed.kind] ?? feed.kind}
                            {feed.has_auth && (
                              <span className="flex items-center gap-0.5 text-amber-400/80">
                                <KeyRound className="h-2.5 w-2.5" /> key
                              </span>
                            )}
                          </p>
                        </div>
                      </div>
                    </td>
                    <td>
                      <FeedStatus feed={feed} />
                    </td>
                    <td className="whitespace-nowrap text-xs text-slate-500">{relativeTime(feed.last_run_at)}</td>
                    <td>
                      <span className="flex items-center gap-1 text-xs text-slate-500">
                        <Timer className="h-3 w-3" /> {feed.schedule_minutes}m
                      </span>
                    </td>
                    <td className="font-mono text-xs text-slate-300">{feed.indicator_count.toLocaleString()}</td>
                    <td>
                      <Toggle
                        checked={feed.enabled}
                        onChange={(value) => update.mutate({ id: feed.id, body: { enabled: value } })}
                        label={`Toggle ${feed.name}`}
                        disabled={update.isPending}
                      />
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-ghost h-8 px-2 text-[10px]"
                        disabled={!feed.enabled || running === feed.id}
                        onClick={() => run.mutate(feed.id)}
                      >
                        {running === feed.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />} Run
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard title="Collection posture" subtitle="Operational notes">
          <div className="space-y-3 text-xs leading-relaxed text-slate-500">
            <p className="flex gap-2">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-mint" />
              Connector credentials are AES-256-GCM encrypted and never serialized back to the browser.
            </p>
            <p className="flex gap-2">
              <Clock3 className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300" />
              Scheduled polling runs every two minutes and respects per-feed schedules. Manual runs are audited.
            </p>
            <p className="flex gap-2">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
              URLhaus is disabled by default because the public endpoint has been unreliable. Enable only with a working endpoint.
            </p>
          </div>
        </SectionCard>

        <SectionCard title="Authenticated sources" subtitle="Require a provider API key">
          <div className="space-y-2">
            {["otx", "abuseipdb", "threatfox", "taxii"].map((kind) => {
              const feed = rows.find((item) => item.kind === kind);
              return (
                <div key={kind} className="flex items-center justify-between rounded-xl border border-ink-600/50 bg-ink-850/40 px-3 py-2.5">
                  <div>
                    <p className="text-xs text-slate-300">{KIND_LABEL[kind]}</p>
                    <p className="mt-0.5 text-[10px] text-slate-600">
                      {feed ? (feed.has_auth ? "Key configured" : "Key required") : "Not configured"}
                    </p>
                  </div>
                  <span className={cn("chip text-[9px]", feed?.enabled ? "border-mint/25 bg-mint/8 text-emerald-300" : "border-ink-600/60 bg-ink-800/50 text-slate-500")}>
                    {feed?.enabled ? "active" : "inactive"}
                  </span>
                </div>
              );
            })}
          </div>
        </SectionCard>
      </div>

      <CreateFeedModal open={createOpen} onClose={() => setCreateOpen(false)} kinds={meta.data?.data.kinds as FeedKind[] | undefined} />
      <ImportCsvModal open={importOpen} onClose={() => setImportOpen(false)} />
    </div>
  );
}

function ImportCsvModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState("Analyst CSV Import");
  const [tlp, setTlp] = useState("amber");
  const upload = useMutation({
    mutationFn: () => api.importCsv(file as File, source.trim(), tlp),
    onSuccess: ({ data }) => {
      toast.success("CSV imported", `${data.created} created, ${data.updated} updated, ${data.rejected} rejected.`);
      setFile(null);
      onClose();
    },
    onError: (error) => toast.error("CSV import failed", error instanceof ApiError ? error.message : undefined),
  });
  return (
    <Modal open={open} onClose={onClose} title="Import IOC CSV" description="Use a header row with value (or indicator/ioc). Optional columns include type, source, confidence, TLP, tags, ATT&CK IDs, notes, first_seen and last_seen.">
      <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); if (file) upload.mutate(); }}>
        <div>
          <label className="label mb-1.5 block">CSV file</label>
          <input type="file" accept=".csv,text/csv" className="input text-xs" required onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label mb-1.5 block">Source name</label>
            <input value={source} onChange={(event) => setSource(event.target.value)} className="input" minLength={2} required />
          </div>
          <div>
            <label className="label mb-1.5 block">Default TLP</label>
            <select value={tlp} onChange={(event) => setTlp(event.target.value)} className="select">
              {['clear', 'green', 'amber', 'red'].map((value) => <option key={value} value={value}>TLP:{value.toUpperCase()}</option>)}
            </select>
          </div>
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={!file || upload.isPending}>
            {upload.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileUp className="h-4 w-4" />} Import
          </button>
        </div>
      </form>
    </Modal>
  );
}

interface FeedKind {
  kind: string;
  reliability: number;
  default_url: string | null;
}

function FeedStatus({ feed }: { feed: Feed }) {
  if (!feed.enabled) return <span className="chip border-ink-600/60 bg-ink-800/50 text-[10px] text-slate-500">paused</span>;
  if (feed.last_status === "ok") {
    return (
      <span className="chip border-mint/25 bg-mint/8 text-[10px] text-emerald-300">
        <CheckCircle2 className="h-3 w-3" /> healthy
      </span>
    );
  }
  if (feed.last_status === "error") {
    return (
      <span className="chip border-rose-400/25 bg-rose-500/8 text-[10px] text-rose-300" title={feed.last_error ?? undefined}>
        <AlertCircle className="h-3 w-3" /> error
      </span>
    );
  }
  return <span className="chip border-ink-600/60 bg-ink-800/50 text-[10px] text-slate-500">pending</span>;
}

function CreateFeedModal({ open, onClose, kinds }: { open: boolean; onClose: () => void; kinds?: FeedKind[] }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [kind, setKind] = useState("demo");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [authKey, setAuthKey] = useState("");
  const [schedule, setSchedule] = useState("60");

  const selected = kinds?.find((item) => item.kind === kind);

  const create = useMutation({
    mutationFn: () =>
      api.createFeed({
        name: name.trim(),
        kind,
        url: url.trim() || undefined,
        auth_key: authKey.trim() || undefined,
        enabled: true,
        schedule_minutes: Number(schedule),
      }),
    onSuccess: () => {
      toast.success("Feed added", "The connector is enabled and will be polled on schedule.");
      setName("");
      setUrl("");
      setAuthKey("");
      void queryClient.invalidateQueries({ queryKey: ["feeds"] });
      onClose();
    },
    onError: (error) => toast.error("Could not add feed", error instanceof ApiError ? error.message : undefined),
  });

  return (
    <Modal open={open} onClose={onClose} title="Add intelligence feed" description="Public feeds work without credentials. Authenticated providers require an API key.">
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (name.trim().length >= 2) create.mutate();
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label mb-1.5 block">Source type</label>
            <select
              value={kind}
              onChange={(event) => {
                setKind(event.target.value);
                setUrl("");
                setAuthKey("");
              }}
              className="select"
            >
              {(kinds ?? Object.keys(KIND_LABEL).map((item) => ({ kind: item, reliability: 0.5, default_url: null }))).map((item) => (
                <option key={item.kind} value={item.kind}>{KIND_LABEL[item.kind] ?? item.kind}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label mb-1.5 block">Display name</label>
            <input value={name} onChange={(event) => setName(event.target.value)} className="input" placeholder="e.g. CISA KEV" required minLength={2} />
          </div>
        </div>
        <div>
          <label className="label mb-1.5 block">Endpoint URL {selected?.default_url ? "(optional)" : ""}</label>
          <input value={url} onChange={(event) => setUrl(event.target.value)} className="input font-mono text-xs" placeholder={selected?.default_url ?? "https://…"} />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label mb-1.5 block">API key</label>
            <input
              value={authKey}
              onChange={(event) => setAuthKey(event.target.value)}
              type="password"
              className="input font-mono text-xs"
              placeholder={["otx", "abuseipdb", "threatfox", "taxii"].includes(kind) ? "Required for this source" : "Not required"}
              disabled={!["otx", "abuseipdb", "threatfox", "taxii"].includes(kind)}
            />
          </div>
          <div>
            <label className="label mb-1.5 block">Schedule (minutes)</label>
            <input value={schedule} onChange={(event) => setSchedule(event.target.value)} type="number" min={5} max={1440} className="input font-mono text-xs" />
          </div>
        </div>
        <div className="rounded-xl border border-ink-600/50 bg-ink-900/50 px-3 py-2 text-[10px] text-slate-500">
          Reliability weight: {selected ? Math.round(selected.reliability * 100) : 50}% · Keys are encrypted before storage.
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={create.isPending}>
            {create.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Add feed
          </button>
        </div>
      </form>
    </Modal>
  );
}
