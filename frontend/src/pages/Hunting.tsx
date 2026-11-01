import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bookmark,
  BookmarkPlus,
  ChevronDown,
  Crosshair,
  Download,
  FileJson,
  Filter,
  Loader2,
  Radar,
  Search,
  SlidersHorizontal,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
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
  TlpBadge,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import type { SavedHunt } from "../lib/types";
import { cn, downloadJson, formatDate, relativeTime, shortValue, typeLabel } from "../lib/utils";

interface HuntFilters {
  q: string;
  type: string;
  severityMin: string;
  tlp: string;
  status: string;
  source: string;
  tag: string;
  attack: string;
  sort: string;
  page: number;
}

const DEFAULT_FILTERS: HuntFilters = {
  q: "",
  type: "",
  severityMin: "",
  tlp: "",
  status: "",
  source: "",
  tag: "",
  attack: "",
  sort: "severity_desc",
  page: 1,
};

const SEVERITY_CHOICES = [
  { value: "80", label: "Critical (80+)" },
  { value: "60", label: "High (60+)" },
  { value: "40", label: "Medium (40+)" },
  { value: "0", label: "All scores" },
];

export function Hunting() {
  const { has } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState<"search" | "attack">("search");
  const [filters, setFilters] = useState<HuntFilters>(() => ({
    ...DEFAULT_FILTERS,
    q: searchParams.get("q") ?? "",
    severityMin: searchParams.get("severity") === "critical" ? "80" : "",
    attack: searchParams.get("attack") ?? "",
    tag: searchParams.get("tag") ?? "",
  }));
  const [qInput, setQInput] = useState(filters.q);
  const [selectedIndicator, setSelectedIndicator] = useState<string | null>(searchParams.get("indicator"));
  const [saveOpen, setSaveOpen] = useState(false);
  const [huntName, setHuntName] = useState("");
  const [exporting, setExporting] = useState<"csv" | "stix" | null>(null);

  const apiParams = useMemo(
    () => ({
      q: filters.q || undefined,
      type: filters.type || undefined,
      severity_min: filters.severityMin || undefined,
      tlp: filters.tlp || undefined,
      status: filters.status || undefined,
      source: filters.source || undefined,
      tag: filters.tag || undefined,
      attack: filters.attack || undefined,
      sort: filters.sort,
      page: filters.page,
      size: 25,
    }),
    [filters],
  );

  const results = useQuery({
    queryKey: ["search", apiParams],
    queryFn: () => api.search(apiParams),
    placeholderData: (previous) => previous,
  });

  const matrix = useQuery({
    queryKey: ["attack-matrix"],
    queryFn: api.attackMatrix,
    enabled: tab === "attack",
  });

  const hunts = useQuery({
    queryKey: ["hunts"],
    queryFn: api.hunts,
    enabled: has("create_hunts"),
  });

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setFilters((current) => (current.q === qInput.trim() ? current : { ...current, q: qInput.trim(), page: 1 }));
    }, 320);
    return () => window.clearTimeout(timer);
  }, [qInput]);

  const patch = (next: Partial<HuntFilters>) => setFilters((current) => ({ ...current, ...next, page: 1 }));

  const reset = () => {
    setFilters(DEFAULT_FILTERS);
    setQInput("");
    setSearchParams({}, { replace: true });
  };

  const saveHunt = useMutation({
    mutationFn: () =>
      api.createHunt({
        name: huntName.trim(),
        query: Object.fromEntries(Object.entries(filters).filter(([, value]) => value !== "" && value !== 1)),
      }),
    onSuccess: () => {
      toast.success("Hunt saved", "You can reload these filters from the saved hunts list.");
      setSaveOpen(false);
      setHuntName("");
      void queryClient.invalidateQueries({ queryKey: ["hunts"] });
    },
    onError: (error) => toast.error("Could not save hunt", error instanceof ApiError ? error.message : undefined),
  });

  const deleteHunt = useMutation({
    mutationFn: (id: string) => api.deleteHunt(id),
    onSuccess: () => {
      toast.success("Saved hunt removed");
      void queryClient.invalidateQueries({ queryKey: ["hunts"] });
    },
    onError: (error) => toast.error("Could not delete hunt", error instanceof ApiError ? error.message : undefined),
  });

  const loadHunt = (hunt: SavedHunt) => {
    const query = hunt.query as Partial<HuntFilters>;
    const next: HuntFilters = {
      ...DEFAULT_FILTERS,
      q: String(query.q ?? ""),
      type: String(query.type ?? ""),
      severityMin: String(query.severityMin ?? ""),
      tlp: String(query.tlp ?? ""),
      status: String(query.status ?? ""),
      source: String(query.source ?? ""),
      tag: String(query.tag ?? ""),
      attack: String(query.attack ?? ""),
      sort: String(query.sort ?? "severity_desc"),
    };
    setFilters(next);
    setQInput(next.q);
    setTab("search");
  };

  const exportData = async (kind: "csv" | "stix") => {
    setExporting(kind);
    try {
      if (kind === "csv") {
        await api.exportCsv(apiParams);
      } else {
        const bundle = await api.exportStix(apiParams);
        downloadJson(bundle, `threatlens-stix-${new Date().toISOString().slice(0, 10)}.json`);
      }
      toast.success(kind === "csv" ? "CSV export started" : "STIX bundle downloaded");
    } catch (error) {
      toast.error("Export failed", error instanceof ApiError ? error.message : undefined);
    } finally {
      setExporting(null);
    }
  };

  const closeIndicator = () => {
    setSelectedIndicator(null);
    if (searchParams.has("indicator")) {
      const next = new URLSearchParams(searchParams);
      next.delete("indicator");
      setSearchParams(next, { replace: true });
    }
  };

  const facets = results.data?.meta.facets ?? {};
  const activeFilterCount = [filters.type, filters.severityMin, filters.tlp, filters.status, filters.source, filters.tag, filters.attack].filter(Boolean).length;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Threat hunting"
        title="Hunt the corpus"
        description="Pivot across sources, ATT&CK techniques, TLP markings and internal sightings. Build repeatable hunts and export evidence for downstream tooling."
        actions={
          <>
            {has("create_hunts") && (
              <button type="button" className="btn-ghost" onClick={() => setSaveOpen(true)}>
                <BookmarkPlus className="h-4 w-4" /> Save hunt
              </button>
            )}
            {has("export") && (
              <>
                <button type="button" className="btn-ghost" onClick={() => void exportData("csv")} disabled={exporting !== null}>
                  {exporting === "csv" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />} CSV
                </button>
                <button type="button" className="btn-primary" onClick={() => void exportData("stix")} disabled={exporting !== null}>
                  {exporting === "stix" ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileJson className="h-4 w-4" />} STIX 2.1
                </button>
              </>
            )}
          </>
        }
      />

      <div className="flex items-center gap-1 border-b border-ink-600/50">
        {[
          { key: "search" as const, label: "Indicator search", icon: Search },
          { key: "attack" as const, label: "ATT&CK coverage", icon: Crosshair },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.key}
              type="button"
              onClick={() => setTab(item.key)}
              className={cn(
                "flex items-center gap-2 border-b-2 px-4 py-2.5 text-xs font-medium transition",
                tab === item.key ? "border-cyan-400 text-cyan-200" : "border-transparent text-slate-500 hover:text-slate-300",
              )}
            >
              <Icon className="h-3.5 w-3.5" /> {item.label}
            </button>
          );
        })}
      </div>

      {tab === "search" ? (
        <div className="grid gap-4 xl:grid-cols-[0.72fr_0.28fr]">
          <div className="space-y-4">
            <SectionCard
              title="Search intelligence"
              subtitle="Full-text and structured query across the cleared corpus"
              action={
                activeFilterCount > 0 ? (
                  <button type="button" className="btn-ghost h-8 px-2 text-[10px]" onClick={reset}>
                    <X className="h-3 w-3" /> Clear {activeFilterCount}
                  </button>
                ) : undefined
              }
            >
              <div className="space-y-3">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                  <input
                    value={qInput}
                    onChange={(event) => setQInput(event.target.value)}
                    placeholder="Search values, domains, hashes, CVEs or notes…"
                    className="input pl-10 pr-10"
                  />
                  {qInput && (
                    <button
                      type="button"
                      onClick={() => setQInput("")}
                      className="absolute right-3 top-3 text-slate-500 hover:text-slate-200"
                      aria-label="Clear query"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  )}
                </div>

                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                  <select value={filters.type} onChange={(event) => patch({ type: event.target.value })} className="select h-9 py-1.5 text-xs">
                    <option value="">All types</option>
                    {["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "cve"].map((type) => (
                      <option key={type} value={type}>{typeLabel(type)}</option>
                    ))}
                  </select>
                  <select value={filters.severityMin} onChange={(event) => patch({ severityMin: event.target.value })} className="select h-9 py-1.5 text-xs">
                    <option value="">Any severity</option>
                    {SEVERITY_CHOICES.map((choice) => (
                      <option key={choice.value} value={choice.value}>{choice.label}</option>
                    ))}
                  </select>
                  <select value={filters.tlp} onChange={(event) => patch({ tlp: event.target.value })} className="select h-9 py-1.5 text-xs">
                    <option value="">All TLP</option>
                    {["clear", "green", "amber", "red"].map((tlp) => (
                      <option key={tlp} value={tlp}>TLP:{tlp.toUpperCase()}</option>
                    ))}
                  </select>
                  <select value={filters.sort} onChange={(event) => setFilters((current) => ({ ...current, sort: event.target.value, page: 1 }))} className="select h-9 py-1.5 text-xs">
                    <option value="severity_desc">Severity high → low</option>
                    <option value="severity_asc">Severity low → high</option>
                    <option value="last_seen_desc">Last seen newest</option>
                    <option value="first_seen_desc">First seen newest</option>
                    <option value="value_asc">Value A → Z</option>
                  </select>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <span className="flex items-center gap-1 text-[10px] uppercase tracking-[0.14em] text-slate-600">
                    <Filter className="h-3 w-3" /> Quick filters
                  </span>
                  <button
                    type="button"
                    onClick={() => patch({ status: filters.status === "active" ? "" : "active" })}
                    className={cn("chip text-[10px]", filters.status === "active" ? "border-cyan-400/30 bg-cyan-400/10 text-cyan-200" : "border-ink-600/60 bg-ink-800/40 text-slate-400")}
                  >
                    Active only
                  </button>
                  <button
                    type="button"
                    onClick={() => patch({ tag: filters.tag === "kev" ? "" : "kev" })}
                    className={cn("chip text-[10px]", filters.tag === "kev" ? "border-rose-400/30 bg-rose-400/10 text-rose-200" : "border-ink-600/60 bg-ink-800/40 text-slate-400")}
                  >
                    KEV tagged
                  </button>
                  {filters.attack && (
                    <button type="button" className="chip border-violet/30 bg-violet/10 text-[10px] text-violet-200" onClick={() => patch({ attack: "" })}>
                      {filters.attack} <X className="h-3 w-3" />
                    </button>
                  )}
                  {filters.tag && filters.tag !== "kev" && (
                    <button type="button" className="chip border-ink-600/60 bg-ink-800/50 text-[10px] text-slate-300" onClick={() => patch({ tag: "" })}>
                      tag: {filters.tag} <X className="h-3 w-3" />
                    </button>
                  )}
                </div>
              </div>
            </SectionCard>

            <SectionCard
              title="Results"
              subtitle={`${results.data?.meta.total ?? 0} matching indicators`}
              bodyClassName="p-0"
              action={
                <span className="flex items-center gap-1 text-[10px] text-slate-600">
                  <SlidersHorizontal className="h-3 w-3" /> {filters.sort.replace("_", " ")}
                </span>
              }
            >
              {results.isLoading ? (
                <div className="p-4"><LoadingPanel rows={7} /></div>
              ) : results.isError ? (
                <div className="p-4">
                  <ErrorPanel
                    message={results.error instanceof ApiError ? results.error.message : "Search failed"}
                    retry={() => void results.refetch()}
                  />
                </div>
              ) : !results.data?.data.length ? (
                <EmptyState
                  title="No indicators match this hunt"
                  description="Broaden the query, lower the severity threshold, or clear TLP and tag filters."
                  icon={<Radar className="h-5 w-5" />}
                />
              ) : (
                <>
                  <div className="table-wrap rounded-none border-0">
                    <table className="data-table min-w-[900px]">
                      <thead>
                        <tr>
                          <th>Indicator</th>
                          <th>Type</th>
                          <th>Severity</th>
                          <th>Conf.</th>
                          <th>Sources</th>
                          <th>Sightings</th>
                          <th>TLP</th>
                          <th>Last seen</th>
                        </tr>
                      </thead>
                      <tbody>
                        {results.data.data.map((indicator) => (
                          <tr key={indicator.id} className="cursor-pointer" onClick={() => setSelectedIndicator(indicator.id)}>
                            <td>
                              <span className="block max-w-[330px] truncate font-mono text-xs text-slate-200">
                                {shortValue(indicator.value, 58)}
                              </span>
                              <span className="mt-0.5 flex flex-wrap items-center gap-1">
                                {(indicator.tags ?? []).slice(0, 3).map((tag) => (
                                  <span key={tag.name} className="rounded border border-ink-600/60 px-1 py-px text-[9px] text-slate-500">
                                    {tag.name}
                                  </span>
                                ))}
                                {(indicator.attack_ids ?? []).slice(0, 2).map((id) => (
                                  <span key={id} className="rounded border border-violet/20 bg-violet/5 px-1 py-px font-mono text-[9px] text-violet-300/80">
                                    {id}
                                  </span>
                                ))}
                              </span>
                            </td>
                            <td className="text-xs text-slate-500">{typeLabel(indicator.type)}</td>
                            <td><SeverityBadge severity={indicator.severity} score={indicator.severity_score} /></td>
                            <td className="font-mono text-xs">{indicator.confidence}%</td>
                            <td className="font-mono text-xs">{indicator.source_count}</td>
                            <td className="font-mono text-xs">{indicator.internal_sightings}</td>
                            <td><TlpBadge tlp={indicator.tlp} /></td>
                            <td className="whitespace-nowrap text-xs text-slate-500">{relativeTime(indicator.last_seen)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <Pagination
                    page={filters.page}
                    size={results.data.meta.size}
                    total={results.data.meta.total}
                    onChange={(page) => setFilters((current) => ({ ...current, page }))}
                  />
                </>
              )}
            </SectionCard>
          </div>

          <div className="space-y-4">
            {has("create_hunts") && (
              <SectionCard title="Saved hunts" subtitle="Reload repeatable queries" bodyClassName="p-2">
                <div className="space-y-1">
                  {(hunts.data?.data ?? []).map((hunt) => (
                    <div key={hunt.id} className="group flex items-center gap-1 rounded-lg px-2 py-1.5 transition hover:bg-ink-800/50">
                      <button type="button" onClick={() => loadHunt(hunt)} className="flex min-w-0 flex-1 items-center gap-2 text-left">
                        <Bookmark className="h-3.5 w-3.5 shrink-0 text-cyan-400/60" />
                        <span className="min-w-0">
                          <span className="block truncate text-[11px] text-slate-300">{hunt.name}</span>
                          <span className="block text-[9px] text-slate-600">{formatDate(hunt.created_at, false)}</span>
                        </span>
                      </button>
                      <button
                        type="button"
                        onClick={() => deleteHunt.mutate(hunt.id)}
                        className="rounded p-1 text-slate-700 opacity-0 transition hover:bg-rose-500/10 hover:text-rose-300 group-hover:opacity-100"
                        aria-label={`Delete ${hunt.name}`}
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  ))}
                  {!hunts.data?.data.length && <p className="px-2 py-6 text-center text-[11px] text-slate-600">No saved hunts yet.</p>}
                </div>
              </SectionCard>
            )}

            <SectionCard title="Facets" subtitle="Refine the current result set" bodyClassName="p-4">
              <div className="space-y-4">
                <FacetGroup title="Types" values={facets.types} active={filters.type} onSelect={(value) => patch({ type: filters.type === value ? "" : value })} />
                <FacetGroup title="TLP" values={facets.tlp} active={filters.tlp} onSelect={(value) => patch({ tlp: filters.tlp === value ? "" : value })} />
                <FacetGroup title="Tags" values={facets.tags} active={filters.tag} onSelect={(value) => patch({ tag: filters.tag === value ? "" : value })} />
                <FacetGroup title="ATT&CK" values={facets.attack} active={filters.attack} onSelect={(value) => patch({ attack: filters.attack === value ? "" : value })} mono />
              </div>
            </SectionCard>
          </div>
        </div>
      ) : (
        <SectionCard
          title="ATT&CK coverage"
          subtitle={
            matrix.data
              ? `${matrix.data.data.mapped_techniques} mapped techniques of ${matrix.data.data.total_techniques} in the corpus`
              : "Enterprise technique coverage"
          }
          bodyClassName="p-4"
        >
          {matrix.isLoading ? (
            <LoadingPanel rows={8} />
          ) : matrix.isError ? (
            <ErrorPanel message="ATT&CK matrix unavailable" retry={() => void matrix.refetch()} />
          ) : (
            <div className="flex gap-3 overflow-x-auto pb-2">
              {(matrix.data?.data.tactics ?? []).map((tactic) => (
                <div key={tactic.id} className="min-w-[170px] flex-1">
                  <div className="mb-2 rounded-xl border border-ink-600/50 bg-ink-850/60 px-3 py-2">
                    <p className="truncate text-[11px] font-semibold text-slate-200">{tactic.name}</p>
                    <p className="mt-0.5 text-[9px] text-slate-600">
                      {tactic.mapped} mapped · {tactic.count} observations
                    </p>
                  </div>
                  <div className="space-y-1.5">
                    {tactic.techniques.map((technique) => (
                      <button
                        key={technique.id}
                        type="button"
                        onClick={() => {
                          patch({ attack: technique.id });
                          setTab("search");
                        }}
                        className="w-full rounded-lg border border-violet/15 bg-violet/[0.045] px-2.5 py-2 text-left transition hover:border-violet/40 hover:bg-violet/10"
                      >
                        <span className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[10px] text-violet-300">{technique.id}</span>
                          <span className="rounded bg-violet/15 px-1.5 py-px font-mono text-[9px] text-violet-200">{technique.count}</span>
                        </span>
                        <span className="mt-0.5 block truncate text-[10px] text-slate-400">{technique.name}</span>
                      </button>
                    ))}
                    {!tactic.techniques.length && (
                      <p className="rounded-lg border border-dashed border-ink-600/40 px-2 py-4 text-center text-[9px] text-slate-600">
                        No mapped techniques
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      )}

      {has("view_indicators") && <IndicatorDrawer indicatorId={selectedIndicator} onClose={closeIndicator} />}

      <Modal open={saveOpen} onClose={() => setSaveOpen(false)} title="Save this hunt" description="Persist the current filters so you can run them again later.">
        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (huntName.trim().length >= 2) saveHunt.mutate();
          }}
        >
          <input
            value={huntName}
            onChange={(event) => setHuntName(event.target.value)}
            className="input"
            placeholder="e.g. Critical KEV infrastructure indicators"
            minLength={2}
            required
          />
          <div className="rounded-xl border border-ink-600/50 bg-ink-900/50 px-3 py-2 text-[10px] text-slate-500">
            {filters.q ? `query: ${filters.q} · ` : ""}
            {filters.type || "all types"} · {filters.severityMin ? `score ≥ ${filters.severityMin}` : "any score"} ·{" "}
            {filters.tlp ? `TLP:${filters.tlp.toUpperCase()}` : "all TLP"}
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn-ghost" onClick={() => setSaveOpen(false)}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={saveHunt.isPending}>
              {saveHunt.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Save hunt
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

function FacetGroup({
  title,
  values,
  active,
  onSelect,
  mono,
}: {
  title: string;
  values?: Array<{ value: string; count: number }>;
  active: string;
  onSelect: (value: string) => void;
  mono?: boolean;
}) {
  if (!values?.length) return null;
  return (
    <div>
      <p className="label mb-1.5 flex items-center gap-1">
        {title} <ChevronDown className="h-2.5 w-2.5" />
      </p>
      <div className="flex flex-wrap gap-1">
        {values.slice(0, 8).map((item) => (
          <button
            key={item.value}
            type="button"
            onClick={() => onSelect(item.value)}
            className={cn(
              "rounded-md border px-1.5 py-0.5 text-[9px] transition",
              active === item.value
                ? "border-cyan-400/30 bg-cyan-400/10 text-cyan-200"
                : "border-ink-600/50 bg-ink-800/40 text-slate-500 hover:text-slate-300",
              mono && "font-mono",
            )}
          >
            {item.value} <span className="opacity-50">{item.count}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
