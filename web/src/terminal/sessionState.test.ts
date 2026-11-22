import { describe, expect, it } from "vitest";

import {
  formatExitReason,
  normalizeStatusDetail,
  sessionStatusView,
  statusFromBackendState,
} from "./sessionState";

describe("sessionState", () => {
  it("maps backend states to user-facing status bar views", () => {
    const signing = sessionStatusView(statusFromBackendState("signing"));
    expect(signing.tone).toBe("connecting");
    expect(signing.detail).toContain("证书");

    const active = sessionStatusView(statusFromBackendState("active"));
    expect(active.tone).toBe("active");
    expect(active.primary).toBe("已连接");
  });

  it("formats exit reasons and exit codes", () => {
    expect(formatExitReason("permission_revoked")).toBe("访问权限已撤销");
    const closed = sessionStatusView({
      phase: "closed",
      detail: "shell_exit",
      exitCode: 0,
    });
    expect(closed.tone).toBe("closed");
    expect(closed.detail).toBe("shell 已退出（退出码 0）");
  });

  it("redacts sensitive bearer/credential details", () => {
    expect(normalizeStatusDetail("Authorization: Bearer osm_secret")).toBe("[已脱敏]");
    expect(normalizeStatusDetail("invalid credentials")).toBe("[已脱敏]");
  });
});
