import type { BackendSessionState } from "../api";

const MAX_DETAIL_LENGTH = 120;

export type SessionPhase =
  | "initializing"
  | "creating"
  | "connecting"
  | "active"
  | "closing"
  | "closed"
  | "error";

export interface SessionStatus {
  phase: SessionPhase;
  backendState?: BackendSessionState;
  detail?: string;
  exitCode?: number;
}

export interface StatusBarView {
  primary: string;
  detail?: string;
  tone: "connecting" | "active" | "closed" | "error";
}

const BACKEND_STATE_LABELS: Record<BackendSessionState, string> = {
  created: "会话已创建，等待通道",
  waiting_agent: "正在通过 Agent 连接 sshd",
  signing: "正在签发短期 SSH 证书",
  ssh_authenticating: "正在验证主机身份并认证",
  active: "会话已就绪",
  closing: "正在关闭会话",
  closed: "会话已结束",
  failed: "会话失败",
};

const EXIT_REASON_LABELS: Record<string, string> = {
  shell_exit: "shell 已退出",
  user_close: "已主动断开",
  admin_close: "已被管理员断开",
  permission_revoked: "访问权限已撤销",
  permission_denied: "无权访问",
  host_key_mismatch: "主机公钥校验失败",
  agent_unavailable: "主机 Agent 离线",
  too_many_streams: "主机并发连接已满",
  ca_sign_failed: "证书签发失败",
  ssh_auth_failed: "SSH 认证失败",
  max_session_duration: "达到最大会话时长",
  browser_disconnected: "浏览器连接已断开",
  terminal_protocol_error: "终端协议错误",
  attach_timeout: "终端附加超时",
  cancelled: "连接已取消",
};

export function normalizeStatusDetail(detail: string): string {
  const normalized = detail.replace(/\s+/g, " ").trim();
  if (
    /authorization\s*:/i.test(normalized) ||
    /\bbearer\s+\S+/i.test(normalized) ||
    /\bcredentials?\b/i.test(normalized)
  ) {
    return "[已脱敏]";
  }
  return normalized.length > MAX_DETAIL_LENGTH
    ? normalized.slice(0, MAX_DETAIL_LENGTH)
    : normalized;
}

export function formatExitReason(reason: string): string {
  return EXIT_REASON_LABELS[reason] ?? normalizeStatusDetail(reason);
}

export function statusFromBackendState(state: BackendSessionState): SessionStatus {
  switch (state) {
    case "active":
      return { phase: "active", backendState: state };
    case "closing":
      return { phase: "closing", backendState: state };
    case "closed":
      return { phase: "closed", backendState: state };
    case "failed":
      return { phase: "error", backendState: state, detail: BACKEND_STATE_LABELS.failed };
    default:
      return { phase: "connecting", backendState: state, detail: BACKEND_STATE_LABELS[state] };
  }
}

export function sessionStatusView(status: SessionStatus): StatusBarView {
  switch (status.phase) {
    case "initializing":
      return { primary: "初始化终端", detail: "正在加载 Ghostty WASM", tone: "connecting" };
    case "creating":
      return { primary: "创建会话", detail: "正在校验授权并申请通道", tone: "connecting" };
    case "connecting":
      return {
        primary: "连接中",
        detail: status.detail
          ? normalizeStatusDetail(status.detail)
          : status.backendState
            ? BACKEND_STATE_LABELS[status.backendState]
            : "正在建立终端通道",
        tone: "connecting",
      };
    case "active":
      return { primary: "已连接", detail: "Ghostty · SSH active", tone: "active" };
    case "closing":
      return { primary: "断开中", detail: "正在关闭 SSH 通道", tone: "closed" };
    case "closed": {
      const base = status.detail ? formatExitReason(status.detail) : "连接已关闭";
      const detail =
        typeof status.exitCode === "number" ? `${base}（退出码 ${status.exitCode}）` : base;
      return { primary: "已断开", detail, tone: "closed" };
    }
    case "error": {
      const base = status.detail ? formatExitReason(status.detail) : "连接失败";
      const detail =
        typeof status.exitCode === "number" ? `${base}（退出码 ${status.exitCode}）` : base;
      return { primary: "失败", detail, tone: "error" };
    }
  }
}
