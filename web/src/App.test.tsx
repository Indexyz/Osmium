import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";

vi.mock("ghostty-web", () => ({
  init: vi.fn(async () => undefined),
  Terminal: vi.fn(function Terminal() {
    return {
      cols: 80,
      rows: 24,
      dispose: vi.fn(),
      focus: vi.fn(),
      loadAddon: vi.fn(),
      onData: vi.fn(() => ({ dispose: vi.fn() })),
      open: vi.fn(),
      reset: vi.fn(),
      write: vi.fn(),
    };
  }),
  FitAddon: vi.fn(function FitAddon() {
    return { fit: vi.fn() };
  }),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe("App", () => {
  it("shows OIDC login view when unauthenticated", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ code: "UNAUTHENTICATED", message: "login required" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        })
      )
    );

    render(<App />);
    const link = await screen.findByRole("link", { name: "使用 OIDC 登录" });
    expect(link).toHaveAttribute("href", "/auth/login");
  });

  it("loads visible hosts and filters by policy labels", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/v1/me") {
        return new Response(
          JSON.stringify({
            user: { id: "u-alice", issuer: "dev", subject: "alice", display_name: "Alice" },
            is_admin: false,
            csrf_token: "csrf-tok",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (url.startsWith("/api/v1/hosts")) {
        return new Response(
          JSON.stringify({
            items: [
              {
                id: "host-123",
                display_name: "prod-web-1",
                status: "ready",
                policy_labels: { env: "prod" },
                allowed_login_users: ["ops", "deploy"],
              },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    expect(await screen.findByText("prod-web-1")).toBeInTheDocument();
    expect(screen.getByText("Alice")).toBeInTheDocument();

    const filterInput = screen.getByPlaceholderText(/label 过滤/);
    fireEvent.change(filterInput, { target: { value: "env=prod role=web" } });
    fireEvent.click(screen.getByRole("button", { name: "刷新" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/hosts?label=env%3Dprod&label=role%3Dweb",
        expect.anything()
      )
    );
  });
});
