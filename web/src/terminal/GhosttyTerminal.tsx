import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import { FitAddon, Terminal, init } from "ghostty-web";

import { clampTerminalSize, type TerminalSize } from "./protocol";

export interface GhosttyTerminalHandle {
  write(data: Uint8Array | string): void;
  reset(): void;
  focus(): void;
  getSize(): TerminalSize | null;
}

interface Props {
  onData(data: string): void;
  onResize(cols: number, rows: number): void;
  onReady?(size: TerminalSize): void;
  onError?(error: Error): void;
}

const TERMINAL_THEME = {
  background: "#101418",
  foreground: "#d8e0e7",
  cursor: "#d8e0e7",
  selectionBackground: "#2c4157",
};

const GhosttyTerminal = forwardRef<GhosttyTerminalHandle, Props>(function GhosttyTerminal(
  { onData, onResize, onReady, onError },
  ref
) {
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const lastSizeRef = useRef<TerminalSize | null>(null);

  const onDataRef = useRef(onData);
  const onResizeRef = useRef(onResize);
  const onReadyRef = useRef(onReady);
  const onErrorRef = useRef(onError);
  onDataRef.current = onData;
  onResizeRef.current = onResize;
  onReadyRef.current = onReady;
  onErrorRef.current = onError;

  useImperativeHandle(ref, () => ({
    write(data: Uint8Array | string) {
      terminalRef.current?.write(data);
    },
    reset() {
      terminalRef.current?.reset();
    },
    focus() {
      terminalRef.current?.focus();
    },
    getSize() {
      const term = terminalRef.current;
      if (!term) {
        return lastSizeRef.current;
      }
      return clampTerminalSize(term.cols, term.rows);
    },
  }));

  useEffect(() => {
    let disposed = false;
    let resizeObserver: ResizeObserver | undefined;
    let dataDisposable: { dispose(): void } | undefined;

    async function mount() {
      try {
        await init();
      } catch (err: unknown) {
        if (!disposed) {
          onErrorRef.current?.(
            err instanceof Error ? err : new Error("Ghostty WASM 初始化失败")
          );
        }
        return;
      }

      if (disposed || !containerRef.current) {
        return;
      }

      const terminal = new Terminal({
        cursorBlink: false,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        fontSize: 14,
        theme: TERMINAL_THEME,
      });
      const fit = new FitAddon();
      terminal.loadAddon(fit);
      terminal.open(containerRef.current);
      dataDisposable = terminal.onData((data) => {
        onDataRef.current(data);
      });
      terminalRef.current = terminal;

      const emitSize = (force: boolean) => {
        fit.fit();
        const size = clampTerminalSize(terminal.cols, terminal.rows);
        const prev = lastSizeRef.current;
        if (!force && prev && prev.cols === size.cols && prev.rows === size.rows) {
          return size;
        }
        lastSizeRef.current = size;
        onResizeRef.current(size.cols, size.rows);
        return size;
      };

      const initialSize = emitSize(true);
      if (typeof ResizeObserver !== "undefined") {
        resizeObserver = new ResizeObserver(() => {
          if (disposed || !containerRef.current) {
            return;
          }
          // Skip collapsed containers so we never send bogus 1x1 resizes while hidden.
          if (
            containerRef.current.clientWidth === 0 ||
            containerRef.current.clientHeight === 0
          ) {
            return;
          }
          emitSize(false);
        });
        resizeObserver.observe(containerRef.current);
      }

      terminal.focus();
      onReadyRef.current?.(initialSize);
    }

    void mount();

    return () => {
      disposed = true;
      resizeObserver?.disconnect();
      dataDisposable?.dispose();
      terminalRef.current?.dispose();
      terminalRef.current = null;
      lastSizeRef.current = null;
    };
  }, []);

  return <div className="terminal" ref={containerRef} />;
});

export default GhosttyTerminal;
