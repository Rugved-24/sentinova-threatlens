import clsx, { type ClassValue } from "clsx";
import type { Role, Severity, Tlp } from "./types";

export function cn(...values: ClassValue[]) {
  return clsx(values);
}

export function formatDate(value: string | null | undefined, withTime = true): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    year: withTime ? undefined : "numeric",
    hour: withTime ? "2-digit" : undefined,
    minute: withTime ? "2-digit" : undefined,
  });
}

export function relativeTime(value: string | null | undefined): string {
  if (!value) return "never";
  const date = new Date(value).getTime();
  if (Number.isNaN(date)) return "—";
  const seconds = Math.round((Date.now() - date) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(value, false);
}

export function formatNumber(value: number | null | undefined): string {
  return new Intl.NumberFormat(undefined, { notation: value && value > 9999 ? "compact" : "standard" }).format(
    value ?? 0,
  );
}

export const SEVERITY: Record<
  Severity,
  { label: string; text: string; bg: string; border: string; dot: string; hex: string }
> = {
  critical: {
    label: "Critical",
    text: "text-rose-300",
    bg: "bg-rose-500/12",
    border: "border-rose-400/35",
    dot: "bg-rose-400",
    hex: "#fb7185",
  },
  high: {
    label: "High",
    text: "text-amber-300",
    bg: "bg-amber-400/10",
    border: "border-amber-300/30",
    dot: "bg-amber-300",
    hex: "#fbbf24",
  },
  medium: {
    label: "Medium",
    text: "text-cyan-300",
    bg: "bg-cyan-400/10",
    border: "border-cyan-300/25",
    dot: "bg-cyan-300",
    hex: "#22d3ee",
  },
  low: {
    label: "Low",
    text: "text-slate-300",
    bg: "bg-slate-400/10",
    border: "border-slate-400/20",
    dot: "bg-slate-400",
    hex: "#94a3b8",
  },
};

export function severityOf(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

export const TLP: Record<Tlp, { label: string; className: string; description: string }> = {
  clear: {
    label: "TLP:CLEAR",
    className: "text-emerald-300 border-emerald-400/30 bg-emerald-400/8",
    description: "Public sharing permitted",
  },
  green: {
    label: "TLP:GREEN",
    className: "text-lime-300 border-lime-400/30 bg-lime-400/8",
    description: "Community sharing permitted",
  },
  amber: {
    label: "TLP:AMBER",
    className: "text-amber-300 border-amber-400/30 bg-amber-400/8",
    description: "Limited internal sharing",
  },
  red: {
    label: "TLP:RED",
    className: "text-rose-300 border-rose-400/30 bg-rose-400/8",
    description: "Named recipients only",
  },
};

export const ROLE_LABEL: Record<Role, string> = {
  admin: "Administrator",
  engineer: "Security Engineer",
  responder: "Incident Responder",
  hunter: "Threat Hunter",
  analyst: "SOC Analyst",
  executive: "Executive",
};

export const PERMISSIONS: Record<Role, Set<string>> = {
  admin: new Set([
    "view_dashboards",
    "search",
    "view_indicators",
    "edit_indicators",
    "tag_indicators",
    "enrich",
    "manage_alerts",
    "read_incidents",
    "manage_incidents",
    "create_hunts",
    "export",
    "generate_reports",
    "configure_feeds",
    "manage_users",
    "view_audit",
    "manage_rules",
  ]),
  engineer: new Set([
    "view_dashboards",
    "search",
    "view_indicators",
    "edit_indicators",
    "tag_indicators",
    "enrich",
    "read_incidents",
    "create_hunts",
    "export",
    "generate_reports",
    "configure_feeds",
    "view_audit",
    "manage_rules",
  ]),
  responder: new Set([
    "view_dashboards",
    "search",
    "view_indicators",
    "edit_indicators",
    "tag_indicators",
    "enrich",
    "manage_alerts",
    "read_incidents",
    "manage_incidents",
    "create_hunts",
    "export",
    "generate_reports",
    "view_audit",
    "manage_rules",
  ]),
  hunter: new Set([
    "view_dashboards",
    "search",
    "view_indicators",
    "tag_indicators",
    "enrich",
    "read_incidents",
    "create_hunts",
    "export",
    "generate_reports",
  ]),
  analyst: new Set([
    "view_dashboards",
    "search",
    "view_indicators",
    "edit_indicators",
    "tag_indicators",
    "enrich",
    "manage_alerts",
    "read_incidents",
    "manage_incidents",
    "create_hunts",
    "export",
    "generate_reports",
  ]),
  executive: new Set(["view_dashboards", "generate_reports"]),
};

export function can(role: Role | undefined, permission: string): boolean {
  if (!role) return false;
  return PERMISSIONS[role].has(permission);
}

export function initials(name: string): string {
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

export function typeLabel(type: string): string {
  return (
    {
      ip: "IP address",
      domain: "Domain",
      url: "URL",
      hash_md5: "MD5 hash",
      hash_sha1: "SHA-1 hash",
      hash_sha256: "SHA-256 hash",
      email: "Email",
      cve: "CVE",
    }[type] ?? type
  );
}

export function shortValue(value: string, max = 52): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

export function downloadJson(value: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function percent(value: number): string {
  return `${Math.round(value)}%`;
}
