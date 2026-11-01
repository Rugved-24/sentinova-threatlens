export type Role = "admin" | "engineer" | "responder" | "hunter" | "analyst" | "executive";
export type Severity = "critical" | "high" | "medium" | "low";
export type Tlp = "clear" | "green" | "amber" | "red";

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  is_active: boolean;
  mfa_enabled: boolean;
  preferences: { widgets?: string[]; [key: string]: unknown };
  last_login_at: string | null;
}

export interface Tag {
  name: string;
  color: string;
}

export interface Indicator {
  id: string;
  value: string;
  type: string;
  severity_score: number;
  severity: Severity;
  confidence: number;
  tlp: Tlp;
  status: string;
  first_seen: string | null;
  last_seen: string | null;
  country: string | null;
  asn: string | null;
  internal_sightings: number;
  source_count: number;
  kev: boolean;
  tags?: Tag[];
  attack_ids?: string[];
  notes?: string | null;
  geo?: Record<string, unknown>;
  malicious_ratio?: number;
  score_breakdown?: {
    components?: Record<string, number>;
    reasons?: string[];
    model?: string;
    age_days?: number;
  };
  sources?: Array<{
    name: string;
    confidence: number;
    reliability: number;
    first_seen: string | null;
    last_seen: string | null;
    raw_ref: string | null;
  }>;
  enrichments?: Array<{
    provider: string;
    kind: string;
    verdict: string | null;
    score: number | null;
    simulated: boolean;
    fetched_at: string | null;
    data: Record<string, unknown>;
  }>;
  relationships?: Array<{
    id: string;
    relation_type: string;
    direction: "in" | "out";
    confidence: number;
    other: { id: string; value: string; type: string; severity_score: number };
  }>;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  score: number;
  status: "new" | "acknowledged" | "in-progress" | "resolved" | "closed";
  tlp: Tlp;
  created_at: string;
  updated_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  rule: string | null;
  assignee: { id: string; name: string } | null;
  incident: { id: string; title: string } | null;
  indicator: {
    id: string;
    value: string;
    type: string;
    severity_score: number;
    internal_sightings: number;
  } | null;
}

export interface Incident {
  id: string;
  title: string;
  summary: string;
  status: "open" | "investigating" | "contained" | "closed";
  severity: Severity;
  owner: { id: string; name: string } | null;
  checklist: Array<{ id: string; label: string; done: boolean }>;
  checklist_done: number;
  checklist_total: number;
  alert_count: number;
  indicator_count: number;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  timeline?: TimelineEntry[];
  alerts?: Alert[];
  indicators?: Indicator[];
}

export interface TimelineEntry {
  id: string;
  event_type: string;
  message: string;
  actor_id: string | null;
  indicator_id: string | null;
  meta: Record<string, unknown>;
  created_at: string;
}

export interface Feed {
  id: string;
  name: string;
  kind: string;
  url: string | null;
  has_auth: boolean;
  enabled: boolean;
  schedule_minutes: number;
  last_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  indicator_count: number;
  config: Record<string, unknown>;
  created_at: string;
}

export interface Report {
  id: string;
  title: string;
  kind: string;
  status: string;
  requested_by: string;
  created_at: string;
  completed_at: string | null;
  download_url: string | null;
}

export interface Notification {
  id: string;
  title: string;
  body: string;
  kind: string;
  read: boolean;
  link: string | null;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor_email: string | null;
  action: string;
  object_type: string | null;
  object_id: string | null;
  ip: string | null;
  correlation_id: string | null;
  detail: Record<string, unknown>;
  entry_hash: string;
  prev_hash: string;
}

export interface ExecutiveData {
  risk_score: number;
  risk_trend: Array<{ date: string; score: number }>;
  counts: {
    active: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    kev: number;
    sightings: number;
    open_incidents: number;
    open_alerts: number;
  };
  trend: Array<{ date: string; count: number; avg_score: number }>;
  categories: Array<{ value: string; count: number }>;
  top_sources: Array<{ value: string; count: number }>;
  heatmap: Array<{
    country: string;
    count: number;
    avg_score: number;
    latitude: number;
    longitude: number;
  }>;
  targets: Array<{ country: string; count: number; latitude: number; longitude: number }>;
  alert_status: Array<{ value: string; count: number }>;
  alert_throughput: Array<{ date: string; raised: number; resolved: number }>;
  attack_top: Array<{ technique_id: string; count: number }>;
  top_indicators: Indicator[];
  generated_at: string;
}

export interface AnalystData {
  counters: {
    new: number;
    unassigned: number;
    mine: number;
    open: number;
    today: number;
  };
  queue: Alert[];
  recent_indicators: Indicator[];
  generated_at: string;
}

export interface GeoData {
  points: Array<{
    country_code: string;
    country_name: string;
    latitude: number;
    longitude: number;
    count: number;
    critical: number;
    high: number;
    avg_score: number;
    simulated: boolean;
  }>;
  total: number;
}

export interface AttackMatrix {
  tactics: Array<{
    id: string;
    name: string;
    mapped: number;
    total: number;
    count: number;
    techniques: Array<{ id: string; name: string; count: number }>;
  }>;
  mapped_techniques: number;
  total_techniques: number;
}

export interface SavedHunt {
  id: string;
  name: string;
  query: Record<string, unknown>;
  created_at: string;
}

export interface Facets {
  [key: string]: Array<{ value: string; count: number }>;
}

export interface SearchResponse {
  data: Indicator[];
  meta: { total: number; page: number; size: number; facets: Facets };
}

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  min_score: number;
  types: string[];
  sources: string[];
  categories: string[];
  tlp_max: Tlp;
  route_roles: Role[];
  route_user_ids: string[];
}

export interface BadgeData {
  new_alerts: number;
  open_incidents: number;
  unread_notifications: number;
}

export interface MetaData {
  version: string;
  demo_mode: boolean;
  feeds_enabled: number;
  feeds_total: number;
  attack_techniques: number;
}
