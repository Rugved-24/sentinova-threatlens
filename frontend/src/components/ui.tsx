import { AlertTriangle, ChevronLeft, ChevronRight, RefreshCw, X } from "lucide-react";
import { useEffect, type ReactNode } from "react";
import { createPortal } from "react-dom";
import type { Severity, Tlp } from "../lib/types";
import { cn, SEVERITY, TLP } from "../lib/utils";

export function SeverityBadge({ severity, score, className }: { severity: Severity; score?: number; className?: string }) {
  const meta = SEVERITY[severity];
  return (
    <span className={cn("chip", meta.bg, meta.border, meta.text, className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", meta.dot)} />
      {meta.label}
      {score !== undefined && <span className="font-mono opacity-70">{score}</span>}
    </span>
  );
}

export function TlpBadge({ tlp, className }: { tlp: Tlp; className?: string }) {
  return <span className={cn("chip", TLP[tlp].className, className)}>{TLP[tlp].label}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "new" || status === "open"
      ? "border-cyan-400/30 bg-cyan-400/10 text-cyan-200"
      : status === "acknowledged" || status === "investigating"
        ? "border-amber-400/30 bg-amber-400/10 text-amber-200"
        : status === "in-progress" || status === "contained"
          ? "border-violet/30 bg-violet/10 text-violet-200"
          : "border-slate-500/30 bg-slate-500/10 text-slate-300";
  return <span className={cn("chip capitalize", tone)}>{status.replace("-", " ")}</span>;
}

export function ScoreRing({
  score,
  size = 132,
  label = "Risk score",
  stroke = 10,
}: {
  score: number;
  size?: number;
  label?: string;
  stroke?: number;
}) {
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
  const severity: Severity = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : "low";
  const color = SEVERITY[severity].hex;
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(148,163,184,0.12)"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-1000 ease-out"
          style={{ filter: `drop-shadow(0 0 8px ${color}55)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-3xl font-semibold tracking-tight text-white">{Math.round(score)}</span>
        <span className="mt-1 text-[10px] uppercase tracking-[0.16em] text-slate-500">{label}</span>
      </div>
    </div>
  );
}

export function StatCard({
  label,
  value,
  hint,
  icon,
  tone = "cyan",
  onClick,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  icon: ReactNode;
  tone?: "cyan" | "rose" | "amber" | "violet" | "mint";
  onClick?: () => void;
}) {
  const tones = {
    cyan: "text-cyan-300 bg-cyan-400/10 border-cyan-400/20",
    rose: "text-rose-300 bg-rose-400/10 border-rose-400/20",
    amber: "text-amber-300 bg-amber-400/10 border-amber-400/20",
    violet: "text-violet-300 bg-violet/10 border-violet/20",
    mint: "text-emerald-300 bg-emerald-400/10 border-emerald-400/20",
  };
  const Component = onClick ? "button" : "div";
  return (
    <Component
      onClick={onClick}
      className={cn(
        "panel panel-hover group flex items-start justify-between p-5 text-left",
        onClick && "cursor-pointer",
      )}
    >
      <div>
        <p className="label">{label}</p>
        <p className="mt-2 font-mono text-2xl font-semibold tracking-tight text-white">{value}</p>
        {hint && <p className="mt-1.5 text-xs text-slate-500">{hint}</p>}
      </div>
      <div className={cn("rounded-xl border p-2.5 transition group-hover:scale-105", tones[tone])}>{icon}</div>
    </Component>
  );
}

export function SectionCard({
  title,
  subtitle,
  action,
  children,
  className,
  bodyClassName,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("panel overflow-hidden", className)}>
      <div className="flex items-center justify-between gap-4 border-b border-ink-600/50 px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
        </div>
        {action}
      </div>
      <div className={cn("p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
      <div>
        {eyebrow && <p className="label mb-2 text-cyan-400/70">{eyebrow}</p>}
        <h1 className="text-2xl font-semibold tracking-tight text-white lg:text-3xl">{title}</h1>
        {description && <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-400">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
  icon,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
      <div className="mb-4 rounded-2xl border border-ink-600/60 bg-ink-800/60 p-3 text-slate-500">{icon}</div>
      <p className="text-sm font-medium text-slate-200">{title}</p>
      {description && <p className="mt-1 max-w-md text-xs leading-relaxed text-slate-500">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function LoadingPanel({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-3", className)}>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton h-14 w-full" style={{ opacity: 1 - index * 0.12 }} />
      ))}
    </div>
  );
}

export function ErrorPanel({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-2xl border border-rose-400/20 bg-rose-500/5 px-6 py-12 text-center">
      <AlertTriangle className="h-6 w-6 text-rose-300" />
      <p className="text-sm text-rose-200">{message}</p>
      {retry && (
        <button type="button" className="btn-ghost" onClick={retry}>
          <RefreshCw className="h-4 w-4" /> Retry
        </button>
      )}
    </div>
  );
}

export function Pagination({
  page,
  size,
  total,
  onChange,
}: {
  page: number;
  size: number;
  total: number;
  onChange: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / Math.max(1, size)));
  return (
    <div className="flex items-center justify-between gap-3 px-1 py-3 text-xs text-slate-500">
      <span>
        {total === 0 ? "0" : (page - 1) * size + 1}–{Math.min(page * size, total)} of {total}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          className="btn-ghost h-8 px-2"
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
          aria-label="Previous page"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        <span className="font-mono text-slate-400">
          {page} / {pages}
        </span>
        <button
          type="button"
          className="btn-ghost h-8 px-2"
          disabled={page >= pages}
          onClick={() => onChange(page + 1)}
          aria-label="Next page"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  width = "max-w-xl",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  width?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handler);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-start justify-center overflow-y-auto bg-ink-950/80 p-4 backdrop-blur-sm sm:items-center">
      <div
        className={cn("panel my-8 w-full animate-fade-up bg-ink-850/95 p-5 shadow-glow sm:my-0", width)}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-white">{title}</h2>
            {description && <p className="mt-1 text-xs leading-relaxed text-slate-500">{description}</p>}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-500 transition hover:bg-ink-700/60 hover:text-white"
            aria-label="Close dialog"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        {children}
      </div>
    </div>,
    document.body,
  );
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  width = "max-w-2xl",
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  width?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[65] flex justify-end bg-ink-950/70 backdrop-blur-sm" onMouseDown={onClose}>
      <div
        className={cn("h-full w-full animate-fade-up overflow-y-auto border-l border-ink-600/70 bg-ink-900/95 p-5 shadow-panel", width)}
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <div className="mb-5 flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="text-lg font-semibold text-white">{title}</div>
            {subtitle && <div className="mt-1 text-xs text-slate-500">{subtitle}</div>}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-500 transition hover:bg-ink-700/60 hover:text-white"
            aria-label="Close panel"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        {children}
      </div>
    </div>,
    document.body,
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition disabled:opacity-50",
        checked ? "border-cyan-400/40 bg-cyan-400/30" : "border-ink-600 bg-ink-700/70",
      )}
    >
      <span
        className={cn(
          "inline-block h-4 w-4 rounded-full bg-white transition",
          checked ? "translate-x-6" : "translate-x-1",
        )}
      />
    </button>
  );
}

export function Sparkline({
  values,
  color = "#22d3ee",
  height = 44,
  className,
}: {
  values: number[];
  color?: string;
  height?: number;
  className?: string;
}) {
  if (!values.length) return null;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = Math.max(1, max - min);
  const points = values
    .map((value, index) => {
      const x = (index / Math.max(1, values.length - 1)) * 100;
      const y = height - ((value - min) / span) * (height - 6) - 3;
      return `${x},${y}`;
    })
    .join(" ");
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" className={cn("w-full", className)} height={height}>
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
