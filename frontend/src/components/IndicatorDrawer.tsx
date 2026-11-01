import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Boxes,
  ExternalLink,
  Fingerprint,
  Link2,
  Loader2,
  Plus,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  Tag as TagIcon,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import type { Tlp } from "../lib/types";
import { cn, formatDate, relativeTime, SEVERITY, shortValue, TLP, typeLabel } from "../lib/utils";
import {
  Drawer,
  ErrorPanel,
  LoadingPanel,
  SeverityBadge,
  StatusBadge,
  TlpBadge,
} from "./ui";

const TABS = ["Overview", "Sources", "Enrichment", "Relationships"] as const;
type Tab = (typeof TABS)[number];

const STATUSES = ["active", "under_review", "whitelisted", "expired"];

export function IndicatorDrawer({
  indicatorId,
  onClose,
}: {
  indicatorId: string | null;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<Tab>("Overview");
  const [notes, setNotes] = useState("");
  const [tag, setTag] = useState("");
  const [relationValue, setRelationValue] = useState("");
  const [relationType, setRelationType] = useState("related-to");
  const { has } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["indicator", indicatorId],
    queryFn: () => api.indicator(indicatorId as string),
    enabled: Boolean(indicatorId),
  });
  const indicator = query.data?.data;

  useEffect(() => {
    if (indicator) setNotes(indicator.notes ?? "");
  }, [indicator]);

  useEffect(() => {
    setTab("Overview");
    setTag("");
    setRelationValue("");
  }, [indicatorId]);

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["indicator", indicatorId] });
    void queryClient.invalidateQueries({ queryKey: ["indicators"] });
    void queryClient.invalidateQueries({ queryKey: ["search"] });
    void queryClient.invalidateQueries({ queryKey: ["executive"] });
  };

  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.updateIndicator(indicatorId as string, body),
    onSuccess: () => {
      toast.success("Indicator updated", "The change was recorded in the audit trail.");
      refresh();
    },
    onError: (error) => toast.error("Update failed", error instanceof ApiError ? error.message : undefined),
  });

  const enrich = useMutation({
    mutationFn: () => api.enrich(indicatorId as string, true),
    onSuccess: () => {
      toast.success("Enrichment complete", "Provider results have been refreshed.");
      refresh();
    },
    onError: (error) => toast.error("Enrichment failed", error instanceof ApiError ? error.message : undefined),
  });

  const relate = useMutation({
    mutationFn: () =>
      api.addRelationship(indicatorId as string, {
        target_value: relationValue.trim(),
        relation_type: relationType,
      }),
    onSuccess: () => {
      toast.success("Relationship created");
      setRelationValue("");
      refresh();
    },
    onError: (error) => toast.error("Could not link indicators", error instanceof ApiError ? error.message : undefined),
  });

  const meta = indicator ? SEVERITY[indicator.severity] : null;
  const components = indicator?.score_breakdown?.components ?? {};
  const reasons = indicator?.score_breakdown?.reasons ?? [];
  const componentLabels: Record<string, string> = {
    source: "Source confidence",
    recency: "Recency",
    verdict: "Vendor verdict",
    sightings: "Internal sightings",
    exploitation: "Active exploitation",
  };

  return (
    <Drawer
      open={Boolean(indicatorId)}
      onClose={onClose}
      width="max-w-3xl"
      title={
        indicator ? (
          <span className="flex items-center gap-2">
            <Fingerprint className="h-4 w-4 text-cyan-300" />
            <span className="font-mono text-sm">{shortValue(indicator.value, 56)}</span>
          </span>
        ) : (
          "Indicator detail"
        )
      }
      subtitle={
        indicator ? (
          <span className="flex flex-wrap items-center gap-2">
            <span>{typeLabel(indicator.type)}</span>
            <span className="text-slate-700">·</span>
            <span>first seen {formatDate(indicator.first_seen)}</span>
            {indicator.kev && <span className="chip border-rose-400/30 bg-rose-500/10 text-rose-300">KEV</span>}
          </span>
        ) : undefined
      }
    >
      {query.isLoading ? (
        <LoadingPanel rows={6} />
      ) : query.isError || !indicator ? (
        <ErrorPanel
          message={query.error instanceof ApiError ? query.error.message : "Indicator could not be loaded"}
          retry={() => void query.refetch()}
        />
      ) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={indicator.severity} score={indicator.severity_score} />
            <TlpBadge tlp={indicator.tlp} />
            <StatusBadge status={indicator.status} />
            <span className="chip border-ink-600/60 bg-ink-800/50 text-slate-400">
              confidence {indicator.confidence}%
            </span>
            <div className="ml-auto flex gap-2">
              {has("enrich") && (
                <button
                  type="button"
                  className="btn-ghost h-8 px-2.5 text-[11px]"
                  onClick={() => enrich.mutate()}
                  disabled={enrich.isPending}
                >
                  {enrich.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
                  Enrich
                </button>
              )}
              <button type="button" className="btn-ghost h-8 px-2.5 text-[11px]" onClick={() => void query.refetch()}>
                <RefreshCw className="h-3.5 w-3.5" /> Refresh
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              ["Sources", indicator.source_count],
              ["Sightings", indicator.internal_sightings],
              ["Confidence", `${indicator.confidence}%`],
              ["Last seen", relativeTime(indicator.last_seen)],
            ].map(([label, value]) => (
              <div key={label} className="rounded-xl border border-ink-600/50 bg-ink-850/50 px-3 py-2.5">
                <p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">{label}</p>
                <p className="mt-1 font-mono text-sm text-slate-200">{value}</p>
              </div>
            ))}
          </div>

          <div className="flex gap-1 overflow-x-auto border-b border-ink-600/50 pb-px">
            {TABS.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => setTab(item)}
                className={cn(
                  "shrink-0 border-b-2 px-3 py-2 text-xs font-medium transition",
                  tab === item
                    ? "border-cyan-400 text-cyan-200"
                    : "border-transparent text-slate-500 hover:text-slate-300",
                )}
              >
                {item}
                {item === "Sources" && <span className="ml-1.5 font-mono text-[10px] opacity-60">{indicator.sources?.length ?? 0}</span>}
                {item === "Relationships" && (
                  <span className="ml-1.5 font-mono text-[10px] opacity-60">{indicator.relationships?.length ?? 0}</span>
                )}
              </button>
            ))}
          </div>

          {tab === "Overview" && (
            <div className="space-y-5">
              <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
                <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <p className="label">Score composition</p>
                    <span className="font-mono text-xs text-slate-500">model 1.0</span>
                  </div>
                  <div className="space-y-3">
                    {Object.entries(componentLabels).map(([key, label]) => {
                      const raw = Number(components[key] ?? 0);
                      const max = key === "source" ? 30 : key === "recency" ? 20 : key === "verdict" ? 25 : key === "sightings" ? 15 : 10;
                      return (
                        <div key={key}>
                          <div className="mb-1 flex items-center justify-between text-[11px]">
                            <span className="text-slate-400">{label}</span>
                            <span className="font-mono text-slate-300">
                              {raw.toFixed(1)} / {max}
                            </span>
                          </div>
                          <div className="h-1.5 overflow-hidden rounded-full bg-ink-700/70">
                            <div
                              className={cn("h-full rounded-full", meta?.dot ?? "bg-cyan-400")}
                              style={{ width: `${Math.min(100, (raw / max) * 100)}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {reasons.length > 0 && (
                    <ul className="mt-4 space-y-1.5 border-t border-ink-600/40 pt-3">
                      {reasons.map((reason) => (
                        <li key={reason} className="flex gap-2 text-[11px] leading-relaxed text-slate-500">
                          <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-cyan-400/60" />
                          {reason}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="space-y-4">
                  <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
                    <p className="label mb-3">Context</p>
                    <dl className="space-y-2.5 text-xs">
                      {[
                        ["Origin", indicator.country || "Unknown"],
                        ["ASN", indicator.asn || "—"],
                        ["Malicious ratio", `${Math.round((indicator.malicious_ratio ?? 0) * 100)}%`],
                        ["First seen", formatDate(indicator.first_seen)],
                        ["Last seen", formatDate(indicator.last_seen)],
                      ].map(([label, value]) => (
                        <div key={label} className="flex items-start justify-between gap-3">
                          <dt className="text-slate-500">{label}</dt>
                          <dd className="text-right font-mono text-slate-300">{value}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>

                  <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
                    <p className="label mb-3 flex items-center gap-2">
                      <TagIcon className="h-3 w-3" /> Tags
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {(indicator.tags ?? []).map((item) => (
                        <span
                          key={item.name}
                          className="chip border-ink-600/60 bg-ink-800/60 text-[10px] text-slate-300"
                          style={{ borderColor: `${item.color}55` }}
                        >
                          {item.name}
                          {has("tag_indicators") && (
                            <button
                              type="button"
                              onClick={() => update.mutate({ remove_tags: [item.name] })}
                              className="ml-0.5 text-slate-600 hover:text-rose-300"
                              aria-label={`Remove ${item.name}`}
                            >
                              <X className="h-2.5 w-2.5" />
                            </button>
                          )}
                        </span>
                      ))}
                      {!indicator.tags?.length && <span className="text-[11px] text-slate-600">No tags</span>}
                    </div>
                    {has("tag_indicators") && (
                      <form
                        className="mt-3 flex gap-2"
                        onSubmit={(event) => {
                          event.preventDefault();
                          if (!tag.trim()) return;
                          update.mutate({ add_tags: [tag.trim()] });
                          setTag("");
                        }}
                      >
                        <input
                          value={tag}
                          onChange={(event) => setTag(event.target.value)}
                          className="input h-8 py-1 text-[11px]"
                          placeholder="Add tag"
                        />
                        <button type="submit" className="btn-ghost h-8 px-2" aria-label="Add tag">
                          <Plus className="h-3.5 w-3.5" />
                        </button>
                      </form>
                    )}
                  </div>
                </div>
              </div>

              {indicator.attack_ids && indicator.attack_ids.length > 0 && (
                <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
                  <p className="label mb-2">ATT&CK techniques</p>
                  <div className="flex flex-wrap gap-1.5">
                    {indicator.attack_ids.map((id) => (
                      <span key={id} className="chip border-violet/25 bg-violet/8 font-mono text-[10px] text-violet-200">
                        {id}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
                <div className="mb-2 flex items-center justify-between">
                  <p className="label">Analyst notes</p>
                  {has("edit_indicators") && (
                    <button
                      type="button"
                      className="btn-ghost h-7 px-2 text-[10px]"
                      disabled={update.isPending || notes === (indicator.notes ?? "")}
                      onClick={() => update.mutate({ notes })}
                    >
                      {update.isPending && <Loader2 className="h-3 w-3 animate-spin" />} Save
                    </button>
                  )}
                </div>
                <textarea
                  value={notes}
                  onChange={(event) => setNotes(event.target.value)}
                  readOnly={!has("edit_indicators")}
                  rows={3}
                  className="input resize-none text-xs leading-relaxed"
                  placeholder="Add investigation context for this indicator…"
                />
              </div>

              {has("edit_indicators") && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label className="label mb-1.5 block">Status</label>
                    <select
                      className="select"
                      value={indicator.status}
                      onChange={(event) => update.mutate({ status: event.target.value })}
                    >
                      {STATUSES.map((status) => (
                        <option key={status} value={status}>
                          {status.replace("_", " ")}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="label mb-1.5 block">TLP handling</label>
                    <select
                      className="select"
                      value={indicator.tlp}
                      onChange={(event) => update.mutate({ tlp: event.target.value as Tlp })}
                    >
                      {Object.entries(TLP).map(([key, value]) => (
                        <option key={key} value={key}>
                          {value.label}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              )}
            </div>
          )}

          {tab === "Sources" && (
            <div className="table-wrap">
              <table className="data-table min-w-[620px]">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Confidence</th>
                    <th>Reliability</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {(indicator.sources ?? []).map((source) => (
                    <tr key={source.name}>
                      <td>
                        <span className="text-xs text-slate-200">{source.name}</span>
                        {source.raw_ref && (
                          <span className="mt-0.5 flex items-center gap-1 truncate text-[10px] text-slate-600">
                            <ExternalLink className="h-2.5 w-2.5" /> {shortValue(source.raw_ref, 50)}
                          </span>
                        )}
                      </td>
                      <td className="font-mono text-xs">{source.confidence}%</td>
                      <td className="font-mono text-xs">{Math.round(source.reliability * 100)}%</td>
                      <td className="text-xs text-slate-500">{relativeTime(source.last_seen)}</td>
                    </tr>
                  ))}
                  {!indicator.sources?.length && (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-xs text-slate-500">
                        No source observations recorded.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {tab === "Enrichment" && (
            <div className="grid gap-3 sm:grid-cols-2">
              {(indicator.enrichments ?? []).map((item) => (
                <div key={`${item.provider}-${item.fetched_at}`} className="rounded-2xl border border-ink-600/50 bg-ink-850/40 p-4">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className="text-xs font-semibold text-slate-200">{item.provider}</p>
                      <p className="mt-0.5 text-[10px] uppercase tracking-[0.12em] text-slate-600">{item.kind}</p>
                    </div>
                    <span
                      className={cn(
                        "chip text-[9px] capitalize",
                        item.verdict === "malicious"
                          ? "border-rose-400/25 bg-rose-500/8 text-rose-300"
                          : "border-ink-600/60 bg-ink-800/60 text-slate-400",
                      )}
                    >
                      {item.verdict ?? "unknown"}
                    </span>
                  </div>
                  <div className="mt-3 flex items-center justify-between text-[11px]">
                    <span className="text-slate-500">Provider score</span>
                    <span className="font-mono text-slate-200">{item.score ?? "—"}</span>
                  </div>
                  {item.simulated && (
                    <p className="mt-2 rounded-lg border border-amber-400/20 bg-amber-400/5 px-2 py-1 text-[9px] text-amber-300/80">
                      Simulated provider response
                    </p>
                  )}
                  <p className="mt-2 text-[9px] text-slate-600">fetched {relativeTime(item.fetched_at)}</p>
                </div>
              ))}
              {!indicator.enrichments?.length && (
                <div className="col-span-full rounded-2xl border border-dashed border-ink-600/60 px-4 py-10 text-center">
                  <Boxes className="mx-auto mb-2 h-5 w-5 text-slate-600" />
                  <p className="text-xs text-slate-500">No enrichment results yet. Run enrichment to query providers.</p>
                </div>
              )}
            </div>
          )}

          {tab === "Relationships" && (
            <div className="space-y-4">
              {has("edit_indicators") && (
                <form
                  className="grid gap-2 rounded-2xl border border-ink-600/50 bg-ink-850/40 p-3 sm:grid-cols-[1fr_150px_auto]"
                  onSubmit={(event) => {
                    event.preventDefault();
                    if (relationValue.trim()) relate.mutate();
                  }}
                >
                  <input
                    value={relationValue}
                    onChange={(event) => setRelationValue(event.target.value)}
                    className="input h-9 py-1.5 text-xs"
                    placeholder="Related indicator value"
                  />
                  <select
                    value={relationType}
                    onChange={(event) => setRelationType(event.target.value)}
                    className="select h-9 py-1.5 text-xs"
                  >
                    {["related-to", "communicates-with", "resolves-to", "drops", "targets", "part-of"].map((type) => (
                      <option key={type} value={type}>
                        {type}
                      </option>
                    ))}
                  </select>
                  <button type="submit" className="btn-primary h-9 px-3 text-xs" disabled={relate.isPending}>
                    {relate.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Link2 className="h-3.5 w-3.5" />}
                    Link
                  </button>
                </form>
              )}
              <div className="space-y-2">
                {(indicator.relationships ?? []).map((relationship) => {
                  const Icon = relationship.direction === "out" ? ArrowUpRight : ArrowDownLeft;
                  return (
                    <div
                      key={relationship.id}
                      className="flex items-center gap-3 rounded-xl border border-ink-600/50 bg-ink-850/40 px-3 py-2.5"
                    >
                      <Icon className="h-3.5 w-3.5 shrink-0 text-cyan-300/70" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-mono text-[11px] text-slate-200">
                          {shortValue(relationship.other.value, 54)}
                        </p>
                        <p className="text-[10px] text-slate-600">
                          {relationship.relation_type} · {typeLabel(relationship.other.type)} · {relationship.confidence}% confidence
                        </p>
                      </div>
                      <span className="flex items-center gap-1 font-mono text-xs text-slate-400">
                        <ShieldAlert className="h-3 w-3" /> {relationship.other.severity_score}
                      </span>
                    </div>
                  );
                })}
                {!indicator.relationships?.length && (
                  <div className="rounded-2xl border border-dashed border-ink-600/60 px-4 py-10 text-center text-xs text-slate-500">
                    No linked indicators. Add a relationship to build the graph.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
}
