import { useState, type FormEvent } from "react";

import type { HostItem } from "../api";

interface Props {
  hosts: HostItem[];
  loading: boolean;
  error: string | null;
  filter: string;
  onFilterChange(value: string): void;
  onRefresh(): void;
  onConnect(host: HostItem, loginUser: string): void;
}

const STATUS_LABELS: Record<HostItem["status"], string> = {
  ready: "ready",
  connecting: "connecting",
  offline: "offline",
  disabled: "disabled",
};

export default function HostsView({
  hosts,
  loading,
  error,
  filter,
  onFilterChange,
  onRefresh,
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
          placeholder="label 过滤，例如 env=prod role=web"
          aria-label="按策略标签过滤主机"
        />
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
                    <button
                      type="button"
                      className="btn btn--primary"
                      disabled={host.status !== "ready" || !login}
                      onClick={() => onConnect(host, login)}
                    >
                      连接
                    </button>
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
    </section>
  );
}
