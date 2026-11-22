import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import TerminalView from "./TerminalView";
import type { HostItem } from "../api";

let onDataCallback: ((data: string) => void) | null = null;

const mockTerminal = {
  cols: 96,
  rows: 30,
  dispose: vi.fn(),
  focus: vi.fn(),
  loadAddon: vi.fn(),
  onData: vi.fn((cb: (data: string) => void) => {
    onDataCallback = cb;
    return { dispose: vi.fn() };
  }),
  open: vi.fn(),
  reset: vi.fn(),
  write: vi.fn(),
};

vi.mock("ghostty-web", () => ({
  init: vi.fn(async () => undefined),
  Terminal: vi.fn(function Terminal() {
    return mockTerminal;
  }),
  FitAddon: vi.fn(function FitAddon() {
    return { fit: vi.fn() };
  }),
}));

class FakeWebSocket {
  static OPEN = 1;
  static CONNECTING = 0;
  static CLOSED = 3;
  static instances: FakeWebSocket[] = [];

  url: string;
  protocol: string;
  binaryType = "blob";
  readyState = FakeWebSocket.CONNECTING;
  sent: Array<string | Uint8Array> = [];
  private listeners: Record<string, Array<(ev: unknown) => void>> = {};

  constructor(url: string, protocol?: string | string[]) {
    this.url = url;
    this.protocol = Array.isArray(protocol) ? protocol[0] : (protocol ?? "");
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type: string, cb: (ev: unknown) => void) {
    (this.listeners[type] ??= []).push(cb);
  }

  send(data: string | Uint8Array) {
    this.sent.push(data);
  }

  close() {
    this.readyState = FakeWebSocket.CLOSED;
  }

  emit(type: string, ev: unknown = {}) {
    if (type === "open") {
      this.readyState = FakeWebSocket.OPEN;
    }
    if (type === "close") {
      this.readyState = FakeWebSocket.CLOSED;
    }
    for (const cb of this.listeners[type] ?? []) {
      cb(ev);
    }
  }
}

const HOST: HostItem = {
  id: "host-123",
  display_name: "prod-web-1",
  status: "ready",
  policy_labels: { env: "prod" },
  allowed_login_users: ["ops"],
};

beforeEach(() => {
  vi.clearAllMocks();
  onDataCallback = null;
  FakeWebSocket.instances = [];
  vi.stubGlobal("WebSocket", FakeWebSocket);
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe = vi.fn();
      disconnect = vi.fn();
    }
  );
});

describe("TerminalView", () => {
  it("gates keyboard input until active, renders binary output and handles exit", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          id: "s-1",
          host_id: "host-123",
          login_user: "ops",
          mode: "web",
          state: "created",
          created_at: "2026-11-22T00:00:00Z",
          terminal_path: "/api/v1/ssh-sessions/s-1/terminal",
          end_reason: null,
        }),
        { status: 201, headers: { "Content-Type": "application/json" } }
      )
    );
    vi.stubGlobal("fetch", fetchMock);

    render(<TerminalView host={HOST} loginUser="ops" csrfToken="csrf-123" onBack={vi.fn()} />);

    await waitFor(() => expect(FakeWebSocket.instances.length).toBe(1));
    const ws = FakeWebSocket.instances[0];
    expect(ws.protocol).toBe("web-ssh-terminal.v1");

    // Verify POST /api/v1/ssh-sessions passed measured Ghostty terminal size.
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({
      host_id: "host-123",
      login_user: "ops",
      terminal: { rows: 30, cols: 96 },
    });

    act(() => {
      ws.emit("open");
      ws.emit("message", {
        data: JSON.stringify({ version: 1, type: "terminal.state", payload: { state: "signing" } }),
      });
    });

    // Input before active must not be transmitted.
    act(() => {
      onDataCallback?.("ls\r");
    });
    expect(ws.sent).toHaveLength(0);

    // Activate session and verify binary I/O works in both directions.
    act(() => {
      ws.emit("message", {
        data: JSON.stringify({ version: 1, type: "terminal.state", payload: { state: "active" } }),
      });
    });
    expect(screen.getByText("已连接")).toBeInTheDocument();

    act(() => {
      onDataCallback?.("id\r");
    });
    expect(ws.sent).toHaveLength(1);
    expect(Array.from(ws.sent[0] as Uint8Array)).toEqual([105, 100, 13]);

    const payload = new Uint8Array([79, 75]).buffer;
    act(() => {
      ws.emit("message", { data: payload });
    });
    expect(mockTerminal.write).toHaveBeenCalledWith(new Uint8Array([79, 75]));

    // Click disconnect sends terminal.close.
    fireEvent.click(screen.getByRole("button", { name: "断开" }));
    expect(JSON.parse(String(ws.sent[1]))).toEqual({
      version: 1,
      type: "terminal.close",
      payload: {},
    });

    // Exit updates status and offers explicit reconnect (no automatic re-attach).
    act(() => {
      ws.emit("message", {
        data: JSON.stringify({
          version: 1,
          type: "terminal.exit",
          payload: { reason: "shell_exit", exit_status: 0 },
        }),
      });
    });
    expect(screen.getByText("已断开")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "重新连接" })).toBeInTheDocument();
  });
});
