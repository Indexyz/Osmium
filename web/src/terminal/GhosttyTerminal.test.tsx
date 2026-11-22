import { render, waitFor } from "@testing-library/react";
import { createRef } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import GhosttyTerminal, { type GhosttyTerminalHandle } from "./GhosttyTerminal";
import { Terminal } from "ghostty-web";

const mockTerminal = {
  cols: 100,
  rows: 32,
  dispose: vi.fn(),
  focus: vi.fn(),
  loadAddon: vi.fn(),
  onData: vi.fn(() => ({ dispose: vi.fn() })),
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

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe = vi.fn();
      disconnect = vi.fn();
    }
  );
});

describe("GhosttyTerminal", () => {
  it("initializes ghostty before opening terminal and reports initial size", async () => {
    const onReady = vi.fn();
    const onResize = vi.fn();

    render(<GhosttyTerminal onData={vi.fn()} onResize={onResize} onReady={onReady} />);

    await waitFor(() => expect(mockTerminal.open).toHaveBeenCalled());
    expect(onResize).toHaveBeenCalledWith(100, 32);
    expect(onReady).toHaveBeenCalledWith({ cols: 100, rows: 32 });
  });

  it("disables local cursor blinking like terminald", async () => {
    render(<GhosttyTerminal onData={vi.fn()} onResize={vi.fn()} />);

    await waitFor(() =>
      expect(Terminal).toHaveBeenCalledWith(
        expect.objectContaining({
          cursorBlink: false,
        })
      )
    );
  });

  it("exposes write and reset through the ref handle", async () => {
    const ref = createRef<GhosttyTerminalHandle>();
    render(<GhosttyTerminal ref={ref} onData={vi.fn()} onResize={vi.fn()} />);

    await waitFor(() => expect(mockTerminal.open).toHaveBeenCalled());
    const chunk = new Uint8Array([65, 66]);
    ref.current?.write(chunk);
    ref.current?.reset();

    expect(mockTerminal.write).toHaveBeenCalledWith(chunk);
    expect(mockTerminal.reset).toHaveBeenCalledTimes(1);
  });
});
