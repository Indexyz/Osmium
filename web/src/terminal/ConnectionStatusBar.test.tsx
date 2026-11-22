import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import ConnectionStatusBar from "./ConnectionStatusBar";

describe("ConnectionStatusBar", () => {
  it("renders active target, phase tone and action buttons", () => {
    const onDisconnect = vi.fn();
    const onReconnect = vi.fn();
    const onBack = vi.fn();

    render(
      <ConnectionStatusBar
        targetLabel="ops@prod-web-1"
        hostId="host-123"
        status={{ phase: "active", backendState: "active" }}
        canDisconnect
        canReconnect={false}
        onDisconnect={onDisconnect}
        onReconnect={onReconnect}
        onBack={onBack}
      />
    );

    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("data-tone", "active");
    expect(screen.getByText("ops@prod-web-1")).toBeInTheDocument();
    expect(screen.getByText("已连接")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "断开" }));
    expect(onDisconnect).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "重新连接" })).not.toBeInTheDocument();
  });

  it("shows reconnect action after session ends", () => {
    const onReconnect = vi.fn();
    render(
      <ConnectionStatusBar
        targetLabel="ops@prod-web-1"
        hostId="host-123"
        status={{ phase: "closed", detail: "shell_exit", exitCode: 0 }}
        canDisconnect={false}
        canReconnect
        onDisconnect={vi.fn()}
        onReconnect={onReconnect}
        onBack={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole("button", { name: "重新连接" }));
    expect(onReconnect).toHaveBeenCalledTimes(1);
  });
});
