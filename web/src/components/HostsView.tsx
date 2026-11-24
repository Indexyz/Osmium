import { useState, type FormEvent } from "react";

import type { HostItem, HostStatus } from "../api";

interface Props {
  hosts: HostItem[];
  total: number;
  pageNumber: number;
  hasPrev: boolean;
  hasNext: boolean;
  loading: boolean;
  error: string | null;
  filter: string;
  statusFilter: "" | HostStatus;
  onFilterChange(value: string): void;
  onStatusFilterChange(value: "" | HostStatus): void;
  onRefresh(): void;
  onPrevPage(): void;
  onNextPage(): void;
  onConnect(host: HostItem, loginUser: string): void;
}

const STATUS_LABELS: Record<HostItem["status"], string> = {
  ready: "ready",
  direct: "direct",
  connecting: "connecting",
  offline: "offline",
  disabled: "disabled",
};

export default function HostsView({
  hosts,
  total,
  pageNumber,
  hasPrev,
  hasNext,
  loading,
  error,
  filter,
  statusFilter,
  onFilterChange,
  onStatusFilterChange,
  onRefresh,
  onPrevPage,
  onNextPage,
  onConnect,
}: Props) {
  const [selectedLogins, setSelectedLogins] = useState<Record<string, string>>({});

  const resolveLogin = (host: HostItem): string => {
    const picked = selectedLogins[host.id];
    if (picked && host.allowed_login_users.includes(picked)) {
      return picked;
    }
    return host.allowed_login_users[0] ?? "";
  };

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    onRefresh();
  };

  return (
    <section className="hosts-view">
      <form className="toolbar" onSubmit={handleSubmit}>
        <input
          id="filter"
          className="input toolbar__search"
          value={filter}
          onChange={(e) => onFilterChange(e.target.value)}
          placeholder="label 过滤或关键字，例如 env=prod role=web prod-1"
          aria-label="按策略标签或主机名称过滤"
        />
        <select
          className="select"
          aria-label="按状态筛选"
          value={statusFilter}
          onChange={(e) => onStatusFilterChange(e.target.value as "" | HostStatus)}
        >
          <option value="">全部状态</option>
          <option value="ready">在线 (ready)</option>
          <option value="direct">直连 (direct)</option>
          <option value="offline">离线 (offline)</option>
          <option value="disabled">已禁用 (disabled)</option>
        </select>
        <button type="submit" className="btn" disabled={loading}>
          {loading ? "加载中…" : "刷新"}
        </button>
      </form>

      {error ? (
        <div className="banner banner--error" role="alert">
          加载主机失败：{error}
        </div>
      ) : null}

      <div className="table-wrap">
        <table className="hosts-table">
          <thead>
            <tr>
              <th>主机</th>
              <th>状态</th>
              <th>Labels</th>
              <th>登录账号</th>
              <th className="hosts-table__action-col" />
            </tr>
          </thead>
          <tbody>
            {hosts.map((host) => {
              const login = resolveLogin(host);
              const labelEntries = Object.entries(host.policy_labels ?? {});
              return (
                <tr key={host.id}>
                  <td>
                    <div className="host-name" title={host.id}>
                      {host.display_name}
                    </div>
                    {host.display_name !== host.id ? (
                      <div className="host-id">{host.id}</div>
                    ) : null}
                  </td>
                  <td>
                    <span className={`host-status host-status--${host.status}`}>
                      <span className="host-status__dot" aria-hidden="true" />
                      {STATUS_LABELS[host.status] ?? host.status}
                    </span>
                  </td>
                  <td>
                    <div className="labels">
                      {labelEntries.length > 0 ? (
                        labelEntries.map(([k, v]) => (
                          <span className="label" key={k}>
                            {k}={v}
                          </span>
                        ))
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </div>
                  </td>
                  <td>
                    <select
                      className="select"
                      aria-label={`${host.display_name} 登录账号`}
                      value={login}
                      onChange={(e) =>
                        setSelectedLogins((prev) => ({ ...prev, [host.id]: e.target.value }))
                      }
                      disabled={host.allowed_login_users.length === 0}
                    >
                      {host.allowed_login_users.map((user) => (
                        <option key={user} value={user}>
                          {user}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="hosts-table__action-col">
                    {host.status === "direct" ? (
                      <button
                        type="button"
                        className="btn"
                        disabled
                        title={`该主机为无 Agent 直连模式，请在终端执行：osmium ssh ${login ? `${login}@` : ""}${host.id}`}
                      >
                        仅 CLI 直连
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="btn btn--primary"
                        disabled={host.status !== "ready" || !login}
                        onClick={() => onConnect(host, login)}
                      >
                        连接
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {!loading && hosts.length === 0 && !error ? (
        <p className="muted empty-state">没有可见的主机。</p>
      ) : null}

      {total > 0 || hasPrev || hasNext ? (
        <div className="pagination">
          <span className="muted pagination__meta">
            共 {total} 台匹配主机 · 第 {pageNumber} 页（本页 {hosts.length} 台）
          </span>
          <div className="pagination__actions">
            <button
              type="button"
              className="btn btn--compact"
              disabled={loading || !hasPrev}
              onClick={onPrevPage}
            >
              上一页
            </button>
            <button
              type="button"
              className="btn btn--compact"
              disabled={loading || !hasNext}
              onClick={onNextPage}
            >
              下一页
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
