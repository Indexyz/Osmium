export interface UserInfo {
  id: string;
  issuer: string;
  subject: string;
  display_name: string;
  groups?: string[];
}

export interface MeResponse {
  user: UserInfo;
  is_admin: boolean;
  csrf_token?: string;
}

export type HostStatus = "ready" | "direct" | "connecting" | "offline" | "disabled";

export type HostConnectionMode = "tunnel" | "direct" | "both";

export interface HostItem {
  id: string;
  display_name: string;
  connection_mode?: HostConnectionMode;
  ssh_address?: string;
  status: HostStatus;
  policy_labels: Record<string, string>;
  allowed_login_users: string[];
}

export type BackendSessionState =
  | "created"
  | "waiting_agent"
  | "signing"
  | "ssh_authenticating"
  | "active"
  | "closing"
  | "closed"
  | "failed";

export interface SessionView {
  id: string;
  host_id: string;
  login_user: string;
  mode: string;
  state: BackendSessionState;
  created_at: string;
  terminal_path?: string;
  end_reason: string | null;
}

export class ApiError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export function generateIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  csrfToken?: string;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(opts.headers ?? {}),
  };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET" && opts.csrfToken) {
    headers["X-CSRF-Token"] = opts.csrfToken;
  }

  const res = await fetch(path, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    credentials: "same-origin",
    signal: opts.signal,
  });

  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    const obj = data && typeof data === "object" ? (data as Record<string, unknown>) : null;
    const msg =
      (obj && typeof obj.message === "string" && obj.message) || res.statusText || `HTTP ${res.status}`;
    const code = obj && typeof obj.code === "string" ? obj.code : undefined;
    throw new ApiError(msg, res.status, code);
  }

  return data as T;
}

export function fetchMe(signal?: AbortSignal): Promise<MeResponse> {
  return request<MeResponse>("/api/v1/me", { signal });
}

export interface HostsPageResponse {
  items: HostItem[];
  next_cursor?: string;
  total: number;
}

export interface HostsQuery {
  filter?: string;
  status?: "" | HostStatus;
  cursor?: string;
  limit?: number;
}

export function parseHostFilterInput(raw: string): { labels: string[]; query: string } {
  const tokens = raw
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  const labels: string[] = [];
  const words: string[] = [];
  for (const t of tokens) {
    const eq = t.indexOf("=");
    if (eq > 0 && eq < t.length - 1) {
      labels.push(t);
    } else {
      words.push(t);
    }
  }
  return { labels, query: words.join(" ") };
}

export function parseLabelFilterInput(raw: string): string[] {
  return parseHostFilterInput(raw).labels;
}

export async function fetchHostsPage(
  opts: HostsQuery = {},
  signal?: AbortSignal
): Promise<HostsPageResponse> {
  const { labels, query } = parseHostFilterInput(opts.filter ?? "");
  const params: string[] = [];
  for (const l of labels) {
    params.push(`label=${encodeURIComponent(l)}`);
  }
  if (query) {
    params.push(`q=${encodeURIComponent(query)}`);
  }
  if (opts.status) {
    params.push(`status=${encodeURIComponent(opts.status)}`);
  }
  if (opts.cursor) {
    params.push(`cursor=${encodeURIComponent(opts.cursor)}`);
  }
  if (opts.limit && opts.limit > 0) {
    params.push(`limit=${opts.limit}`);
  }
  const path = params.length > 0 ? `/api/v1/hosts?${params.join("&")}` : "/api/v1/hosts";
  const data = await request<Partial<HostsPageResponse>>(path, { signal });
  const items = data.items ?? [];
  return {
    items,
    next_cursor: data.next_cursor || undefined,
    total: typeof data.total === "number" ? data.total : items.length,
  };
}

export async function fetchHosts(labelFilter: string, signal?: AbortSignal): Promise<HostItem[]> {
  const page = await fetchHostsPage({ filter: labelFilter }, signal);
  return page.items;
}

export function createSession(
  params: { hostId: string; loginUser: string; rows: number; cols: number },
  csrfToken: string,
  signal?: AbortSignal
): Promise<SessionView> {
  return request<SessionView>("/api/v1/ssh-sessions", {
    method: "POST",
    csrfToken,
    headers: { "Idempotency-Key": generateIdempotencyKey() },
    body: {
      host_id: params.hostId,
      login_user: params.loginUser,
      terminal: { rows: params.rows, cols: params.cols },
    },
    signal,
  });
}

export async function logout(csrfToken: string): Promise<void> {
  await request<null>("/auth/logout", { method: "POST", csrfToken });
}
