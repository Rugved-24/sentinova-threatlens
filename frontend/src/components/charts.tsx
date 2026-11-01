import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type Row = Record<string, string | number>;

interface TooltipPayload {
  name?: string;
  value?: number | string;
  color?: string;
  dataKey?: string | number;
}

function ChartTooltip({
  active,
  payload,
  label,
  suffix = "",
}: {
  active?: boolean;
  payload?: TooltipPayload[];
  label?: string | number;
  suffix?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-xl border border-ink-600/80 bg-ink-900/95 px-3 py-2 shadow-panel backdrop-blur">
      {label !== undefined && <p className="mb-1 text-[10px] uppercase tracking-[0.14em] text-slate-500">{label}</p>}
      {payload.map((item) => (
        <div key={String(item.dataKey ?? item.name)} className="flex items-center gap-2 text-xs">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: item.color }} />
          <span className="capitalize text-slate-400">{item.name}</span>
          <span className="ml-auto font-mono text-slate-100">
            {typeof item.value === "number" ? item.value.toLocaleString() : item.value}
            {suffix}
          </span>
        </div>
      ))}
    </div>
  );
}

export function TrendArea({
  data,
  xKey,
  series,
  height = 260,
  suffix = "",
  yDomain,
}: {
  data: Row[];
  xKey: string;
  series: Array<{ key: string; name: string; color: string }>;
  height?: number;
  suffix?: string;
  yDomain?: [number, number];
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -22, bottom: 0 }}>
        <defs>
          {series.map((item) => (
            <linearGradient key={item.key} id={`area-${item.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={item.color} stopOpacity={0.32} />
              <stop offset="100%" stopColor={item.color} stopOpacity={0.02} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey={xKey}
          axisLine={false}
          tickLine={false}
          tick={{ fill: "#64748b", fontSize: 10 }}
          tickFormatter={(value: string) => value.slice(5)}
          minTickGap={22}
        />
        <YAxis axisLine={false} tickLine={false} tick={{ fill: "#64748b", fontSize: 10 }} domain={yDomain} width={48} />
        <Tooltip content={<ChartTooltip suffix={suffix} />} cursor={{ stroke: "rgba(34,211,238,0.18)" }} />
        {series.map((item) => (
          <Area
            key={item.key}
            type="monotone"
            dataKey={item.key}
            name={item.name}
            stroke={item.color}
            strokeWidth={1.8}
            fill={`url(#area-${item.key})`}
            dot={false}
            activeDot={{ r: 3, strokeWidth: 0 }}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function TrendBars({
  data,
  xKey,
  series,
  height = 250,
  stacked = true,
}: {
  data: Row[];
  xKey: string;
  series: Array<{ key: string; name: string; color: string }>;
  height?: number;
  stacked?: boolean;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -24, bottom: 0 }} barGap={2}>
        <CartesianGrid strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey={xKey}
          axisLine={false}
          tickLine={false}
          tick={{ fill: "#64748b", fontSize: 10 }}
          tickFormatter={(value: string) => value.slice(5)}
          minTickGap={22}
        />
        <YAxis axisLine={false} tickLine={false} tick={{ fill: "#64748b", fontSize: 10 }} width={46} allowDecimals={false} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(34,211,238,0.04)" }} />
        {series.map((item) => (
          <Bar
            key={item.key}
            dataKey={item.key}
            name={item.name}
            fill={item.color}
            radius={[3, 3, 0, 0]}
            stackId={stacked ? "stack" : undefined}
            maxBarSize={22}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

export function Donut({
  data,
  height = 220,
  centerLabel,
  centerValue,
}: {
  data: Array<{ name: string; value: number; color: string }>;
  height?: number;
  centerLabel?: string;
  centerValue?: string | number;
}) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  return (
    <div className="relative" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius="62%"
            outerRadius="86%"
            paddingAngle={2}
            stroke="none"
          >
            {data.map((item) => (
              <Cell key={item.name} fill={item.color} />
            ))}
          </Pie>
          <Tooltip content={<ChartTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-2xl font-semibold text-white">{centerValue ?? total}</span>
        <span className="mt-1 text-[10px] uppercase tracking-[0.16em] text-slate-500">{centerLabel ?? "Total"}</span>
      </div>
    </div>
  );
}

export function HBar({
  data,
  height = 220,
  color = "#22d3ee",
}: {
  data: Array<{ name: string; value: number }>;
  height?: number;
  color?: string;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, left: 6, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" axisLine={false} tickLine={false} tick={{ fill: "#64748b", fontSize: 10 }} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="name"
          axisLine={false}
          tickLine={false}
          tick={{ fill: "#94a3b8", fontSize: 10 }}
          width={96}
        />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(34,211,238,0.04)" }} />
        <Bar dataKey="value" name="Indicators" fill={color} radius={[0, 4, 4, 0]} maxBarSize={16} />
      </BarChart>
    </ResponsiveContainer>
  );
}
