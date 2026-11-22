import { describe, expect, it } from "vitest";

import {
  clampTerminalSize,
  decodeServerMessage,
  encodeClose,
  encodeInput,
  encodeResize,
  resolveTerminalWsUrl,
} from "./protocol";

describe("terminal protocol", () => {
  it("clamps terminal dimensions to backend 1..1000 range", () => {
    expect(clampTerminalSize(0, -5)).toEqual({ cols: 1, rows: 1 });
    expect(clampTerminalSize(1200, 1001)).toEqual({ cols: 1000, rows: 1000 });
    expect(clampTerminalSize(120.4, 38.6)).toEqual({ cols: 120, rows: 39 });
    expect(clampTerminalSize(Number.NaN, Number.POSITIVE_INFINITY)).toEqual({ cols: 80, rows: 24 });
  });

  it("encodes input as UTF-8 bytes", () => {
    expect(Array.from(encodeInput("ls\r"))).toEqual([108, 115, 13]);
  });

  it("encodes resize and close matching internal/protocol/terminal.go", () => {
    expect(JSON.parse(encodeResize(120, 40))).toEqual({
      version: 1,
      type: "terminal.resize",
      payload: { rows: 40, cols: 120 },
    });
    expect(JSON.parse(encodeClose())).toEqual({
      version: 1,
      type: "terminal.close",
      payload: {},
    });
  });

  it("decodes valid terminal.state and terminal.exit messages", () => {
    expect(
      decodeServerMessage(
        JSON.stringify({ version: 1, type: "terminal.state", payload: { state: "active" } })
      )
    ).toEqual({ type: "terminal.state", state: "active" });

    expect(
      decodeServerMessage(
        JSON.stringify({
          version: 1,
          type: "terminal.exit",
          payload: { reason: "shell_exit", exit_status: 0 },
        })
      )
    ).toEqual({ type: "terminal.exit", reason: "shell_exit", exitStatus: 0 });
  });

  it("rejects malformed or unsupported server frames", () => {
    expect(decodeServerMessage("not-json")).toBeNull();
    expect(
      decodeServerMessage(
        JSON.stringify({ version: 2, type: "terminal.state", payload: { state: "active" } })
      )
    ).toBeNull();
    expect(
      decodeServerMessage(
        JSON.stringify({ version: 1, type: "terminal.state", payload: { state: "bogus" } })
      )
    ).toBeNull();
  });

  it("resolves ws/wss URLs from relative terminal_path", () => {
    expect(
      resolveTerminalWsUrl("/api/v1/ssh-sessions/s-1/terminal", {
        protocol: "https:",
        host: "ssh.example.com",
      })
    ).toBe("wss://ssh.example.com/api/v1/ssh-sessions/s-1/terminal");

    expect(
      resolveTerminalWsUrl("/api/v1/ssh-sessions/s-1/terminal", {
        protocol: "http:",
        host: "127.0.0.1:8080",
      })
    ).toBe("ws://127.0.0.1:8080/api/v1/ssh-sessions/s-1/terminal");

    expect(() =>
      resolveTerminalWsUrl("https://evil.example/ws", {
        protocol: "https:",
        host: "ssh.example.com",
      })
    ).toThrow();
  });
});
