import { useCallback, useEffect, useRef, useState } from "react";

import { createSession, type HostItem } from "../api";
import ConnectionStatusBar from "./ConnectionStatusBar";
import GhosttyTerminal, { type GhosttyTerminalHandle } from "./GhosttyTerminal";
import {
  TERMINAL_SUBPROTOCOL,
  clampTerminalSize,
  decodeServerMessage,
  encodeClose,
  encodeInput,
  encodeResize,
  resolveTerminalWsUrl,
  type TerminalSize,
} from "./protocol";
import { statusFromBackendState, type SessionStatus } from "./sessionState";

interface Props {
  host: HostItem;
  loginUser: string;
  csrfToken: string;
  onBack(): void;
}

const CLEAN_EXIT_REASONS = new Set(["shell_exit", "user_close"]);

export default function TerminalView({ host, loginUser, csrfToken, onBack }: Props) {
  const terminalRef = useRef<GhosttyTerminalHandle>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const isActiveRef = useRef(false);
  const latestSizeRef = useRef<TerminalSize>({ cols: 80, rows: 24 });
  const sentSizeRef = useRef<TerminalSize | null>(null);

  const [terminalReady, setTerminalReady] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [status, setStatus] = useState<SessionStatus>({ phase: "initializing" });

  const handleTerminalReady = useCallback((size: TerminalSize) => {
    latestSizeRef.current = size;
    setTerminalReady(true);
  }, []);

  const handleTerminalError = useCallback((error: Error) => {
    setStatus({ phase: "error", detail: error.message });
  }, []);

  const sendInput = useCallback((data: string) => {
    const socket = socketRef.current;
    // Protocol requirement: only forward keyboard bytes once the SSH session is active.
    if (!isActiveRef.current || !socket || socket.readyState !== WebSocket.OPEN) {
      return;
    }
    socket.send(encodeInput(data));
  }, []);

  const sendResize = useCallback((cols: number, rows: number) => {
    const size = clampTerminalSize(cols, rows);
    latestSizeRef.current = size;
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return;
    }
    const prev = sentSizeRef.current;
    if (prev && prev.cols === size.cols && prev.rows === size.rows) {
      return;
    }
    sentSizeRef.current = size;
    socket.send(encodeResize(size.cols, size.rows));
  }, []);

  const handleDisconnect = useCallback(() => {
    abortRef.current?.abort();
    const socket = socketRef.current;
    if (socket && socket.readyState === WebSocket.OPEN) {
      setStatus({ phase: "closing", backendState: "closing" });
      socket.send(encodeClose());
    } else if (socket && socket.readyState === WebSocket.CONNECTING) {
      socket.close();
      setStatus({ phase: "closed", detail: "user_close" });
    }
  }, []);

  const handleReconnect = useCallback(() => {
    terminalRef.current?.reset();
    setAttempt((n) => n + 1);
  }, []);

  useEffect(() => {
    if (!terminalReady) {
      return;
    }

    let cancelled = false;
    let receivedExit = false;
    let sawActive = false;
    isActiveRef.current = false;
    sentSizeRef.current = null;

    const controller = new AbortController();
    abortRef.current = controller;

    async function connect() {
      const initialSize = clampTerminalSize(
        latestSizeRef.current.cols,
        latestSizeRef.current.rows
      );
      sentSizeRef.current = initialSize;
      setStatus({ phase: "creating" });

      let session;
      try {
        session = await createSession(
          {
            hostId: host.id,
            loginUser,
            rows: initialSize.rows,
            cols: initialSize.cols,
          },
          csrfToken,
          controller.signal
        );
      } catch (err: unknown) {
        if (cancelled || controller.signal.aborted) {
          return;
        }
        setStatus({
          phase: "error",
          detail: err instanceof Error ? err.message : "创建会话失败",
        });
        return;
      }

      if (cancelled) {
        return;
      }

      if (!session.terminal_path) {
        setStatus({ phase: "error", detail: "服务端未返回终端地址" });
        return;
      }

      let wsUrl: string;
      try {
        wsUrl = resolveTerminalWsUrl(session.terminal_path);
      } catch (err: unknown) {
        setStatus({
          phase: "error",
          detail: err instanceof Error ? err.message : "无效的终端路径",
        });
        return;
      }

      setStatus({ phase: "connecting", backendState: session.state });

      const socket = new WebSocket(wsUrl, TERMINAL_SUBPROTOCOL);
      socket.binaryType = "arraybuffer";
      socketRef.current = socket;

      socket.addEventListener("open", () => {
        if (cancelled) {
          socket.close();
          return;
        }
        const current = latestSizeRef.current;
        const sent = sentSizeRef.current;
        if (!sent || current.cols !== sent.cols || current.rows !== sent.rows) {
          sentSizeRef.current = current;
          socket.send(encodeResize(current.cols, current.rows));
        }
      });

      socket.addEventListener("message", (event) => {
        if (cancelled) {
          return;
        }
        if (typeof event.data === "string") {
          const msg = decodeServerMessage(event.data);
          if (!msg) {
            return;
          }
          if (msg.type === "terminal.state") {
            if (msg.state === "active") {
              sawActive = true;
              isActiveRef.current = true;
              terminalRef.current?.focus();
            } else if (
              msg.state === "closing" ||
              msg.state === "closed" ||
              msg.state === "failed"
            ) {
              isActiveRef.current = false;
            }
            if (!receivedExit) {
              setStatus(statusFromBackendState(msg.state));
            }
          } else if (msg.type === "terminal.exit") {
            receivedExit = true;
            isActiveRef.current = false;
            const isClean = CLEAN_EXIT_REASONS.has(msg.reason);
            setStatus({
              phase: isClean ? "closed" : "error",
              backendState: isClean ? "closed" : "failed",
              detail: msg.reason,
              exitCode: msg.exitStatus,
            });
          }
          return;
        }

        if (event.data instanceof ArrayBuffer) {
          terminalRef.current?.write(new Uint8Array(event.data));
        } else if (event.data instanceof Blob) {
          void event.data.arrayBuffer().then((buf) => {
            if (!cancelled) {
              terminalRef.current?.write(new Uint8Array(buf));
            }
          });
        }
      });

      socket.addEventListener("close", () => {
        if (socketRef.current === socket) {
          socketRef.current = null;
        }
        isActiveRef.current = false;
        if (cancelled || receivedExit) {
          return;
        }
        setStatus({
          phase: sawActive ? "closed" : "error",
          detail: sawActive ? "连接已关闭" : "终端连接中断",
        });
      });

      socket.addEventListener("error", () => {
        if (cancelled || receivedExit) {
          return;
        }
        if (!sawActive) {
          setStatus({ phase: "error", detail: "WebSocket 连接失败" });
        }
      });
    }

    void connect();

    return () => {
      cancelled = true;
      isActiveRef.current = false;
      controller.abort();
      if (abortRef.current === controller) {
        abortRef.current = null;
      }
      const socket = socketRef.current;
      if (socket) {
        socketRef.current = null;
        if (socket.readyState === WebSocket.OPEN) {
          try {
            socket.send(encodeClose());
          } catch {
            // ignore close frame write error during unmount
          }
        }
        socket.close();
      }
    };
  }, [attempt, csrfToken, host.id, loginUser, terminalReady]);

  const canDisconnect =
    status.phase === "creating" ||
    status.phase === "connecting" ||
    status.phase === "active";
  const canReconnect =
    terminalReady && (status.phase === "closed" || status.phase === "error");

  return (
    <main className="terminal-shell" data-status={status.phase}>
      <ConnectionStatusBar
        targetLabel={`${loginUser}@${host.display_name}`}
        hostId={host.id}
        status={status}
        canDisconnect={canDisconnect}
        canReconnect={canReconnect}
        onDisconnect={handleDisconnect}
        onReconnect={handleReconnect}
        onBack={onBack}
      />
      <GhosttyTerminal
        ref={terminalRef}
        onData={sendInput}
        onResize={sendResize}
        onReady={handleTerminalReady}
        onError={handleTerminalError}
      />
    </main>
  );
}
