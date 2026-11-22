import type { BackendSessionState } from "../api";

export const TERMINAL_SUBPROTOCOL = "web-ssh-terminal.v1";

export const MIN_TERMINAL_DIM = 1;
export const MAX_TERMINAL_DIM = 1000;

export interface TerminalSize {
  cols: number;
  rows: number;
}

export type ServerTerminalMessage =
  | { type: "terminal.state"; state: BackendSessionState }
  | { type: "terminal.exit"; reason: string; exitStatus?: number };

const VALID_STATES = new Set<BackendSessionState>([
  "created",
  "waiting_agent",
  "signing",
  "ssh_authenticating",
  "active",
  "closing",
  "closed",
  "failed",
]);

const textEncoder = new TextEncoder();

export function clampTerminalSize(cols: number, rows: number): TerminalSize {
  const safeCols = Number.isFinite(cols) ? Math.round(cols) : 80;
  const safeRows = Number.isFinite(rows) ? Math.round(rows) : 24;
  return {
    cols: Math.min(MAX_TERMINAL_DIM, Math.max(MIN_TERMINAL_DIM, safeCols)),
    rows: Math.min(MAX_TERMINAL_DIM, Math.max(MIN_TERMINAL_DIM, safeRows)),
  };
}

export function encodeInput(data: string): Uint8Array {
  return textEncoder.encode(data);
}

export function encodeResize(cols: number, rows: number): string {
  const clamped = clampTerminalSize(cols, rows);
  return JSON.stringify({
    version: 1,
    type: "terminal.resize",
    payload: { rows: clamped.rows, cols: clamped.cols },
  });
}

export function encodeClose(): string {
  return JSON.stringify({
    version: 1,
    type: "terminal.close",
    payload: {},
  });
}

export function decodeServerMessage(raw: string): ServerTerminalMessage | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") {
    return null;
  }
  const env = parsed as Record<string, unknown>;
  if (env.version !== 1 || !env.payload || typeof env.payload !== "object") {
    return null;
  }
  const payload = env.payload as Record<string, unknown>;

  if (env.type === "terminal.state") {
    if (typeof payload.state === "string" && VALID_STATES.has(payload.state as BackendSessionState)) {
      return { type: "terminal.state", state: payload.state as BackendSessionState };
    }
    return null;
  }

  if (env.type === "terminal.exit") {
    if (typeof payload.reason !== "string") {
      return null;
    }
    const exitStatus = typeof payload.exit_status === "number" ? payload.exit_status : undefined;
    return { type: "terminal.exit", reason: payload.reason, exitStatus };
  }

  return null;
}

export function resolveTerminalWsUrl(
  terminalPath: string,
  loc: Pick<Location, "protocol" | "host"> = window.location
): string {
  if (!terminalPath.startsWith("/")) {
    throw new Error("invalid terminal path");
  }
  const proto = loc.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${loc.host}${terminalPath}`;
}
