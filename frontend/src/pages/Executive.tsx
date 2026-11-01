import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Download,
  FileText,
  Flame,
  Globe2,
  Loader2,
  Radar,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Swords,
  Target,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Donut, HBar, TrendArea, TrendBars } from "../components/charts";
import { IndicatorDrawer } from "../components/IndicatorDrawer";
import { WorldHeatmap } from "../components/WorldHeatmap";
import {
  EmptyState,
  ErrorPanel,
  PageHeader,
  ScoreRing,
  SectionCard,
  SeverityBadge,
  StatCard,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api, ApiError } from "../lib/api";
import type { Severity } from "../lib/types";
import { cn, formatDate, formatNumber, relativeTime, SEVERITY, severityOf, shortValue } from "../lib/utils";

const DASHBOARD_WIDGETS = [
  { id: "posture", label: "Risk posture banner" },
  { id: "kpis", label: "Key risk indicators" },
  { id: "risk", label: "Composite score and trajectory" },
  { id: "mix", label: "Severity, throughput and sources" },
  { id: "heatmap", label: "Global origin heatmap" },
  { id: "indicators", label: "Priority indicators and ATT&CK pressure" },
] as const;

const DEFAULT_WIDGETS = DASHBOARD_WIDGETS.map((widget) => widget.id);
const KNOWN_WIDGETS = new Set<string>(DEFAULT_WIDGETS);

function normalizeWidgets(value: unknown): string[] {
  if (!Array.isArray(value)) return DEFAULT_WIDGETS;
  const selected = value.filter(
    (id): id is string => typeof id === "string" && KNOWN_WIDGETS.has(id),
  );
  if (selected.length === 0 || selected.length !== value.length) return DEFAULT_WIDGETS;
  return selected;
}

export function Executive() {
  const { has, user, refreshUser } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const [selectedIndicator, setSelectedIndicator] = useState<string | null>(null);
  const [customizeOpen, setCustomizeOpen] = useState(false);
  const [widgets, setWidgets] = useState<string[]>(() =>
    normalizeWidgets(user?.preferences.widgets),
  );

  useEffect(() => {
    setWidgets(normalizeWidgets(user?.preferences.widgets));
  }, [user?.preferences.widgets]);

  const saveWidgets = useMutation({
    mutationFn: (next: string[]) =>
      api.profile({ preferences: { ...user?.preferences, widgets: next } }),
    onSuccess: async () => {
      await refreshUser();
      setCustomizeOpen(false);
      toast.success("Dashboard updated", "Your widget selection is saved to your profile.");
    },
    onError: (error) =>
      toast.error("Could not save dashboard", error instanceof ApiError ? error.message : undefined),
  });

  const show = (id: string) => widgets.includes(id);

  const executive = useQuery({ queryKey: ["executive"], queryFn: api.executive, refetchInterval: 60_000 });
  const geo = useQuery({ queryKey: ["geo"], queryFn: api.geo, refetchInterval: 120_000 });
  const data = executive.data?.data;

  const report = useMutation({
    mutationFn: () =>
      api.createReport({
        kind: "executive",
        title: `Executive Threat Brief · ${new Date().toLocaleDateString()}`,
      }),
    onSuccess: async (response) => {
      toast.success("Executive brief generated", "Your PDF download should begin shortly.");
      if (response.data.download_url) {
        await api.downloadReport(response.data.id, response.data.title).catch(() =>
          toast.error("Report generated, but the download failed"),
        );
      }
    },
    onError: (error) => toast.error("Report generation failed", error instanceof ApiError ? error.message : undefined),
  });

  if (executive.isLoading) {
    return (
      <div className="space-y-5">
        <div className="skeleton h-20 w-full" />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, index) => (
            <div key={index} className="skeleton h-28 w-full" />
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="skeleton h-72" />
          <div className="skeleton h-72 lg:col-span-2" />
        </div>
      </div>
    );
  }

  if (executive.isError || !data) {
    return (
      <ErrorPanel
        message={executive.error instanceof ApiError ? executive.error.message : "Executive dashboard unavailable"}
        retry={() => void executive.refetch()}
      />
    );
  }

  const severity = severityOf(data.risk_score);
  const severityData = (["critical", "high", "medium", "low"] as Severity[]).map((key) => ({
    name: SEVERITY[key].label,
    value: data.counts[key],
    color: SEVERITY[key].hex,
  }));
  const posture =
    data.risk_score >= 80
      ? "Elevated exposure. Immediate containment review recommended."
      : data.risk_score >= 60
        ? "Active threat pressure. Prioritise critical and KEV-linked indicators."
        : data.risk_score >= 40
          ? "Managed risk. Continue monitoring and targeted hunting."
          : "Low observed risk across cleared intelligence sources.";

  const topAttack = data.attack_top.slice(0, 6);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Executive intelligence"
        title="Risk posture overview"
        description="A decision-grade view of the threat landscape. Indicators are scored for source confidence, recency, vendor verdict, internal sightings and active exploitation."
        actions={
          <>
            <button
              type="button"
              className="btn-ghost"
              onClick={() => setCustomizeOpen((value) => !value)}
              aria-expanded={customizeOpen}
            >
              <SlidersHorizontal className="h-4 w-4" /> Customize
            </button>
            <button
              type="button"
              className="btn-ghost"
              onClick={() => navigate(has("search") ? "/hunting" : "/reports")}
            >
              <Radar className="h-4 w-4" /> {has("search") ? "Open hunting" : "View reports"}
            </button>
            {has("generate_reports") && (
              <button type="button" className="btn-primary" onClick={() => report.mutate()} disabled={report.isPending}>
                {report.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                Generate brief
              </button>
            )}
          </>
        }
      />

      {customizeOpen && (
        <SectionCard
          title="Dashboard widgets"
          subtitle="Choose the panels shown on your executive overview. Preferences are saved to your profile."
        >
          <div className="grid gap-2 sm:grid-cols-2">
            {DASHBOARD_WIDGETS.map((widget) => {
              const checked = widgets.includes(widget.id);
              return (
                <label
                  key={widget.id}
                  className="flex cursor-pointer items-center gap-3 rounded-xl border border-ink-600/50 bg-ink-900/40 px-3 py-2.5 text-xs text-slate-300 transition hover:border-cyan-400/30"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() =>
                      setWidgets((current) =>
                        current.includes(widget.id)
                          ? current.filter((id) => id !== widget.id)
                          : [...current, widget.id],
                      )
                    }
                    className="h-4 w-4 accent-cyan-400"
                  />
                  {widget.label}
                </label>
              );
            })}
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button
              type="button"
              className="btn-primary"
              onClick={() => saveWidgets.mutate(widgets)}
              disabled={saveWidgets.isPending || widgets.length === 0}
            >
              {saveWidgets.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Save layout
            </button>
            <button type="button" className="btn-ghost" onClick={() => setWidgets(DEFAULT_WIDGETS)}>
              Restore defaults
            </button>
            <span className="text-[10px] text-slate-500">At least one widget must remain visible.</span>
          </div>
        </SectionCard>
      )}

      {show("posture") && (
      <div
        className={cn(
          "flex flex-col justify-between gap-3 rounded-2xl border px-5 py-4 sm:flex-row sm:items-center",
          severity === "critical"
            ? "border-rose-400/25 bg-rose-500/[0.055]"
            : severity === "high"
              ? "border-amber-400/25 bg-amber-400/[0.045]"
              : "border-cyan-400/20 bg-cyan-400/[0.035]",
        )}
      >
        <div className="flex items-start gap-3">
          <div className={cn("mt-0.5 rounded-xl border p-2", SEVERITY[severity].border, SEVERITY[severity].bg)}>
            <ShieldAlert className={cn("h-4 w-4", SEVERITY[severity].text)} />
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-300">
              {SEVERITY[severity].label} risk posture
            </p>
            <p className="mt-1 text-xs text-slate-500">{posture}</p>
          </div>
        </div>
        <div className="flex items-center gap-5 text-[10px] uppercase tracking-[0.12em] text-slate-500">
          <span>
            <span className="block text-base font-semibold normal-case tracking-normal text-slate-200">
              {formatNumber(data.counts.kev)}
            </span>
            KEV linked
          </span>
          <span>
            <span className="block text-base font-semibold normal-case tracking-normal text-slate-200">
              {formatNumber(data.counts.sightings)}
            </span>
            internal sightings
          </span>
          <span className="hidden sm:block">
            <span className="block text-base font-semibold normal-case tracking-normal text-slate-200">
              {relativeTime(data.generated_at)}
            </span>
            generated
          </span>
        </div>
      </div>
      )}

      {show("kpis") && (
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Active indicators"
          value={formatNumber(data.counts.active)}
          hint="Cleared intelligence corpus"
          icon={<Radar className="h-4 w-4" />}
        />
        <StatCard
          label="Critical severity"
          value={formatNumber(data.counts.critical)}
          hint={`${data.counts.high} high severity`}
          icon={<Flame className="h-4 w-4" />}
          tone="rose"
          onClick={has("search") ? () => navigate("/hunting?severity=critical") : undefined}
        />
        <StatCard
          label="Open incidents"
          value={formatNumber(data.counts.open_incidents)}
          hint="Coordinated response cases"
          icon={<Swords className="h-4 w-4" />}
          tone="amber"
          onClick={has("read_incidents") ? () => navigate("/incidents") : undefined}
        />
        <StatCard
          label="Open alerts"
          value={formatNumber(data.counts.open_alerts)}
          hint="Awaiting triage or resolution"
          icon={<AlertTriangle className="h-4 w-4" />}
          tone="violet"
          onClick={has("manage_alerts") ? () => navigate("/analyst") : undefined}
        />
      </div>
      )}

      {show("risk") && (
      <div className="grid gap-4 lg:grid-cols-[0.78fr_1.22fr]">
        <SectionCard title="Composite risk score" subtitle="Weighted across the cleared corpus">
          <div className="flex flex-col items-center gap-5 sm:flex-row lg:flex-col">
            <ScoreRing score={data.risk_score} size={154} label="Risk index" />
            <div className="w-full space-y-2.5">
              {[
                ["Critical", data.counts.critical, SEVERITY.critical.hex],
                ["High", data.counts.high, SEVERITY.high.hex],
                ["Medium", data.counts.medium, SEVERITY.medium.hex],
                ["Low", data.counts.low, SEVERITY.low.hex],
              ].map(([label, value, color]) => {
                const numeric = Number(value);
                const pct = data.counts.active ? (numeric / data.counts.active) * 100 : 0;
                return (
                  <div key={String(label)}>
                    <div className="mb-1 flex items-center justify-between text-[11px]">
                      <span className="text-slate-400">{label}</span>
                      <span className="font-mono text-slate-300">{numeric}</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-ink-700/70">
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: String(color) }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="mt-5 flex items-center gap-2 rounded-xl border border-ink-600/50 bg-ink-900/50 px-3 py-2.5 text-[10px] text-slate-500">
            <ShieldCheck className="h-3.5 w-3.5 text-mint" />
            Risk index combines average severity and critical concentration.
          </div>
        </SectionCard>

        <SectionCard
          title="Risk trajectory"
          subtitle="Seven-day rolling average of indicator severity"
          action={
            <span className="chip border-cyan-400/20 bg-cyan-400/5 text-[10px] text-cyan-300">
              <Activity className="h-3 w-3" /> 30 days
            </span>
          }
        >
          <TrendArea
            data={data.risk_trend}
            xKey="date"
            series={[{ key: "score", name: "Risk index", color: "#22d3ee" }]}
            height={264}
            yDomain={[0, 100]}
          />
        </SectionCard>
      </div>
      )}

      {show("mix") && (
      <div className="grid gap-4 lg:grid-cols-3">
        <SectionCard title="Severity mix" subtitle="Distribution of active indicators">
          <Donut data={severityData} centerLabel="active" centerValue={formatNumber(data.counts.active)} height={220} />
          <div className="mt-2 grid grid-cols-2 gap-2">
            {severityData.map((item) => (
              <div key={item.name} className="flex items-center justify-between rounded-lg border border-ink-600/40 px-2.5 py-1.5">
                <span className="flex items-center gap-1.5 text-[10px] text-slate-500">
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: item.color }} />
                  {item.name}
                </span>
                <span className="font-mono text-[11px] text-slate-300">{item.value}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="Alert throughput" subtitle="Raised versus resolved over 14 days">
          <TrendBars
            data={data.alert_throughput}
            xKey="date"
            series={[
              { key: "raised", name: "Raised", color: "#fb7185" },
              { key: "resolved", name: "Resolved", color: "#34d399" },
            ]}
            height={222}
            stacked={false}
          />
          <div className="mt-3 flex items-center gap-4 text-[10px] text-slate-500">
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-rose-400" /> Raised
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Resolved
            </span>
          </div>
        </SectionCard>

        <SectionCard title="Top sources" subtitle="Distinct indicators contributed">
          {data.top_sources.length > 0 ? (
            <HBar
              data={data.top_sources.slice(0, 6).map((item) => ({ name: shortValue(item.value, 15), value: item.count }))}
              height={222}
              color="#a78bfa"
            />
          ) : (
            <EmptyState title="No source observations" icon={<Globe2 className="h-5 w-5" />} />
          )}
        </SectionCard>
      </div>
      )}

      {show("heatmap") && (
      <SectionCard
        title="Global origin heatmap"
        subtitle="Indicator origin by country · simulated coordinates for demonstration data"
        action={
          <span className="chip border-ink-600/60 bg-ink-800/50 text-[10px] text-slate-400">
            <Globe2 className="h-3 w-3" /> {geo.data?.data.total ?? data.heatmap.length} locations
          </span>
        }
      >
        <WorldHeatmap points={geo.data?.data.points ?? []} />
      </SectionCard>
      )}

      {show("indicators") && (
      <div className="grid gap-4 lg:grid-cols-[1.35fr_0.65fr]">
        <SectionCard
          title="Highest-scoring indicators"
          subtitle="Prioritised for validation and response"
          action={
            has("search") ? (
              <button type="button" className="btn-ghost h-8 px-2.5 text-[11px]" onClick={() => navigate("/hunting")}>
                Open search <ArrowUpRight className="h-3.5 w-3.5" />
              </button>
            ) : undefined
          }
          bodyClassName="p-0"
        >
          {data.top_indicators.length > 0 ? (
            <div className="table-wrap rounded-none border-0">
              <table className="data-table min-w-[680px]">
                <thead>
                  <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Sources</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_indicators.slice(0, 8).map((indicator) => (
                    <tr
                      key={indicator.id}
                      className={has("view_indicators") ? "cursor-pointer" : undefined}
                      onClick={() => has("view_indicators") && setSelectedIndicator(indicator.id)}
                    >
                      <td>
                        <span className="block max-w-[300px] truncate font-mono text-xs text-slate-200">
                          {shortValue(indicator.value, 54)}
                        </span>
                        {indicator.kev && <span className="mt-0.5 text-[9px] text-rose-400">Known exploited</span>}
                      </td>
                      <td className="text-xs text-slate-500">{indicator.type}</td>
                      <td>
                        <SeverityBadge severity={indicator.severity} score={indicator.severity_score} />
                      </td>
                      <td className="font-mono text-xs">{indicator.source_count}</td>
                      <td className="text-xs text-slate-500">{relativeTime(indicator.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="No indicators in your clearance"
              description="Executive accounts receive aggregate reporting without raw indicator values."
              icon={<Target className="h-5 w-5" />}
            />
          )}
        </SectionCard>

        <div className="space-y-4">
          <SectionCard title="ATT&CK pressure" subtitle="Most observed techniques">
            {topAttack.length > 0 ? (
              <div className="space-y-2.5">
                {topAttack.map((item, index) => (
                  <div key={item.technique_id} className="flex items-center gap-3">
                    <span className="w-4 text-right font-mono text-[10px] text-slate-600">{index + 1}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[11px] text-violet-200">{item.technique_id}</span>
                        <span className="font-mono text-[10px] text-slate-500">{item.count}</span>
                      </div>
                      <div className="mt-1 h-1 overflow-hidden rounded-full bg-ink-700/60">
                        <div
                          className="h-full rounded-full bg-violet/70"
                          style={{ width: `${(item.count / Math.max(...topAttack.map((row) => row.count))) * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No ATT&CK mappings" icon={<Target className="h-5 w-5" />} />
            )}
          </SectionCard>

          <SectionCard title="Indicator categories" subtitle="Composition by type">
            {data.categories.length > 0 ? (
              <div className="space-y-2">
                {data.categories.slice(0, 6).map((item) => (
                  <div key={item.value} className="flex items-center justify-between rounded-lg border border-ink-600/40 px-2.5 py-1.5">
                    <span className="text-[11px] capitalize text-slate-400">{item.value.replace("_", " ")}</span>
                    <span className="font-mono text-[11px] text-slate-300">{item.count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No category data" icon={<FileText className="h-5 w-5" />} />
            )}
          </SectionCard>
        </div>
      </div>
      )}

      <p className="px-1 text-[10px] text-slate-600">
        Generated {formatDate(data.generated_at)} · Intelligence is synthetic demonstration data. Handling caveats are
        enforced at the API and reflected in every aggregate.
      </p>

      {has("view_indicators") && (
        <IndicatorDrawer indicatorId={selectedIndicator} onClose={() => setSelectedIndicator(null)} />
      )}
    </div>
  );
}
