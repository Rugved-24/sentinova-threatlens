import type {
  Alert,
  AlertRule,
  AnalystData,
  AttackMatrix,
  AuditEntry,
  BadgeData,
  ExecutiveData,
  Facets,
  Feed,
  GeoData,
  Incident,
  Indicator,
  MetaData,
  Notification,
  Report,
  Role,
  SavedHunt,
  SearchResponse,
  TimelineEntry,
  User,
} from "./types";

const BASE = "/api/v1";
let accessToken: string | null = null;
let refreshPromise: Promise<boolean> | null = null;

export class ApiError extends Error {
  status: number;
  code: string;
  details?: unknown;

  constructor(message: string, status: number, code = "request_failed", details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken() {
  return accessToken;
}

function queryString(params?: Record<string, unknown>): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null && item !== "") search.append(key, String(item));
      }
    } else {
      search.append(key, String(value));
    }
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

async function rawFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const url = path.startsWith("/api/") || path.startsWith("http") ? path : `${BASE}${path}`;
  return fetch(url, { ...init, headers, credentials: "include" });
}

export async function refreshSession(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    try {
      const response = await fetch(`${BASE}/auth/refresh`, {
        method: "POST",
        credentials: "include",
      });
      if (!response.ok) {
        setAccessToken(null);
        return false;
      }
      const body = (await response.json()) as { access_token: string };
      setAccessToken(body.access_token);
      return true;
    } catch {
      setAccessToken(null);
      return false;
    } finally {
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

async function parseError(response: Response): Promise<ApiError> {
  let message = `Request failed (${response.status})`;
  let code = "request_failed";
  let details: unknown;
  try {
    const body = await response.json();
    message = body.message || message;
    code = body.error_code || code;
    details = body.errors;
  } catch {
    // Keep the status-based message when the body is not JSON.
  }
  return new ApiError(message, response.status, code, details);
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  params?: Record<string, unknown>,
  retry = true,
): Promise<T> {
  const response = await rawFetch(`${path}${queryString(params)}`, init);
  if (response.status === 401 && retry && !path.includes("/auth/")) {
    const refreshed = await refreshSession();
    if (refreshed) return request<T>(path, init, params, false);
  }
  if (!response.ok) throw await parseError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function jsonBody(body: unknown): RequestInit {
  return { method: "POST", body: JSON.stringify(body) };
}

function patchBody(body: unknown): RequestInit {
  return { method: "PATCH", body: JSON.stringify(body) };
}

export interface LoginResult {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export const api = {
  login: (email: string, password: string, otp?: string) =>
    request<LoginResult>("/auth/login", jsonBody({ email, password, otp: otp || undefined }), undefined, false),
  refresh: refreshSession,
  logout: async () => {
    try {
      await request<void>("/auth/logout", { method: "POST" }, undefined, false);
    } finally {
      setAccessToken(null);
    }
  },
  me: () => request<{ data: User }>("/auth/me"),
  profile: (body: { name?: string; preferences?: Record<string, unknown> }) =>
    request<{ data: User }>("/auth/profile", patchBody(body)),
  changePassword: (body: { current_password: string; new_password: string }) =>
    request<{ data: { changed: boolean } }>("/auth/change-password", jsonBody(body)),
  mfaSetup: () => request<{ data: { secret: string; otpauth_url: string } }>("/auth/mfa/setup", { method: "POST" }),
  mfaEnable: (code: string) => request<{ data: { mfa_enabled: boolean } }>("/auth/mfa/enable", jsonBody({ code })),
  mfaDisable: (password: string, code: string) =>
    request<{ data: { mfa_enabled: boolean } }>("/auth/mfa/disable", jsonBody({ password, code })),

  executive: () => request<{ data: ExecutiveData }>("/dashboards/executive"),
  analyst: () => request<{ data: AnalystData }>("/dashboards/analyst"),
  geo: () => request<{ data: GeoData }>("/dashboards/geo"),
  attackMatrix: () => request<{ data: AttackMatrix }>("/attack/matrix"),
  techniques: (params: { q?: string; ids?: string[] }) =>
    request<{ data: Array<Record<string, unknown>> }>("/attack/techniques", {}, params),

  indicators: (params: Record<string, unknown>) => request<SearchResponse>("/indicators", {}, params),
  search: (params: Record<string, unknown>) => request<SearchResponse>("/search", {}, params),
  indicator: (id: string) => request<{ data: Indicator }>(`/indicators/${id}`),
  updateIndicator: (id: string, body: Record<string, unknown>) =>
    request<{ data: Indicator }>(`/indicators/${id}`, patchBody(body)),
  enrich: (id: string, force = false) =>
    request<{ data: Indicator }>(`/indicators/${id}/enrich?force=${force}`, { method: "POST" }),
  addRelationship: (id: string, body: Record<string, unknown>) =>
    request<{ data: Indicator }>(`/indicators/${id}/relationships`, jsonBody(body)),
  graph: (id: string, depth = 2) =>
    request<{ data: { nodes: Array<Record<string, unknown>>; edges: Array<Record<string, unknown>> } }>(
      `/indicators/${id}/graph`,
      {},
      { depth },
    ),

  alerts: (params: Record<string, unknown>) =>
    request<{ data: Alert[]; meta: { total: number; page: number; size: number } }>("/alerts", {}, params),
  alert: (id: string) => request<{ data: Alert }>(`/alerts/${id}`),
  updateAlert: (id: string, body: Record<string, unknown>) =>
    request<{ data: Alert }>(`/alerts/${id}`, patchBody(body)),
  escalateAlert: (id: string, body: Record<string, unknown>) =>
    request<{ data: Incident }>(`/alerts/${id}/escalate`, jsonBody(body)),
  rules: () => request<{ data: AlertRule[] }>("/alert-rules"),
  createRule: (body: Record<string, unknown>) => request<{ data: AlertRule }>("/alert-rules", jsonBody(body)),
  updateRule: (id: string, body: Record<string, unknown>) =>
    request<{ data: AlertRule }>(`/alert-rules/${id}`, patchBody(body)),

  incidents: (params: Record<string, unknown> = {}) =>
    request<{ data: Incident[]; meta: { total: number; page: number; size: number } }>("/incidents", {}, params),
  incident: (id: string) => request<{ data: Incident }>(`/incidents/${id}`),
  createIncident: (body: Record<string, unknown>) => request<{ data: Incident }>("/incidents", jsonBody(body)),
  updateIncident: (id: string, body: Record<string, unknown>) =>
    request<{ data: Incident }>(`/incidents/${id}`, patchBody(body)),
  addTimeline: (id: string, body: Record<string, unknown>) =>
    request<{ data: TimelineEntry }>(`/incidents/${id}/timeline`, jsonBody(body)),

  feeds: () => request<{ data: Feed[] }>("/feeds"),
  feedMeta: () => request<{ data: Record<string, unknown> }>("/feeds/meta"),
  createFeed: (body: Record<string, unknown>) => request<{ data: Feed }>("/feeds", jsonBody(body)),
  updateFeed: (id: string, body: Record<string, unknown>) =>
    request<{ data: Feed }>(`/feeds/${id}`, patchBody(body)),
  runFeed: (id: string) => request<{ data: { status: string } }>(`/feeds/${id}/run`, { method: "POST" }),
  importCsv: (file: File, source: string, tlp: string) => {
    const body = new FormData();
    body.append("file", file);
    body.append("source", source);
    body.append("tlp", tlp);
    return request<{ data: { rows: number; created: number; updated: number; rejected: number; alerts: number } }>(
      "/feeds/import/csv",
      { method: "POST", body },
    );
  },

  reports: () => request<{ data: Report[] }>("/reports"),
  createReport: (body: Record<string, unknown>) => request<{ data: Report }>("/reports", jsonBody(body)),
  downloadReport: async (id: string, title: string) => {
    const response = await rawFetch(`/reports/${id}/download`);
    if (!response.ok) throw await parseError(response);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${title.replace(/[^a-z0-9 _-]/gi, "").trim() || "threatlens-report"}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  },

  users: () => request<{ data: User[] }>("/users"),
  createUser: (body: Record<string, unknown>) => request<{ data: User }>("/users", jsonBody(body)),
  updateUser: (id: string, body: Record<string, unknown>) =>
    request<{ data: User }>(`/users/${id}`, patchBody(body)),
  resetMfa: (id: string) => request<{ data: { mfa_enabled: boolean } }>(`/users/${id}/reset-mfa`, { method: "POST" }),

  audit: (params: Record<string, unknown>) =>
    request<{ data: AuditEntry[]; meta: { total: number; page: number; size: number } }>("/audit", {}, params),
  verifyAudit: () =>
    request<{ data: { valid: boolean; entries: number; head?: string; broken_at?: number; message: string } }>(
      "/audit/verify",
    ),

  notifications: (unreadOnly = false) =>
    request<{ data: Notification[] }>("/notifications", {}, { unread_only: unreadOnly }),
  readNotifications: (ids: string[] = [], all = false) =>
    request<{ data: { updated: number } }>("/notifications/read", patchBody({ ids, all })),
  badges: () => request<{ data: BadgeData }>("/badges"),
  meta: () => request<{ data: MetaData }>("/meta"),

  hunts: () => request<{ data: SavedHunt[] }>("/hunts"),
  createHunt: (body: { name: string; query: Record<string, unknown> }) =>
    request<{ data: SavedHunt }>("/hunts", jsonBody(body)),
  deleteHunt: (id: string) => request<void>(`/hunts/${id}`, { method: "DELETE" }),

  exportStix: (params: Record<string, unknown>) => request<Record<string, unknown>>("/export/stix", {}, params),
  exportCsv: async (params: Record<string, unknown>) => {
    const response = await rawFetch(`/export/csv${queryString(params)}`);
    if (!response.ok) throw await parseError(response);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `threatlens-indicators-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  },
};

export type { Facets, Role };
