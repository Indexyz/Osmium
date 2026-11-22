import { useCallback, useEffect, useState } from "react";

import {
  ApiError,
  fetchHosts,
  fetchMe,
  logout,
  type HostItem,
  type MeResponse,
} from "./api";
import HostsView from "./components/HostsView";
import LoginView from "./components/LoginView";
import TerminalView from "./terminal/TerminalView";

interface ActiveTarget {
  host: HostItem;
  loginUser: string;
}

export default function App() {
  const [authLoading, setAuthLoading] = useState(true);
  const [me, setMe] = useState<MeResponse | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  const [filter, setFilter] = useState("");
  const [hosts, setHosts] = useState<HostItem[]>([]);
  const [hostsLoading, setHostsLoading] = useState(false);
  const [hostsError, setHostsError] = useState<string | null>(null);

  const [target, setTarget] = useState<ActiveTarget | null>(null);

  const loadHosts = useCallback(async (currentFilter: string) => {
    setHostsLoading(true);
    setHostsError(null);
    try {
      const items = await fetchHosts(currentFilter);
      setHosts(items);
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 401) {
        setMe(null);
        setTarget(null);
        return;
      }
      setHostsError(err instanceof Error ? err.message : "加载主机失败");
    } finally {
      setHostsLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    async function init() {
      try {
        const info = await fetchMe(controller.signal);
        setMe(info);
        await loadHosts("");
      } catch (err: unknown) {
        if (controller.signal.aborted) {
          return;
        }
        if (err instanceof ApiError && err.status === 401) {
          setMe(null);
        } else {
          setAuthError(err instanceof Error ? err.message : "加载登录状态失败");
        }
      } finally {
        if (!controller.signal.aborted) {
          setAuthLoading(false);
        }
      }
    }
    void init();
    return () => controller.abort();
  }, [loadHosts]);

  const handleLogout = useCallback(async () => {
    if (me?.csrf_token) {
      try {
        await logout(me.csrf_token);
      } catch {
        // Always clear client state on logout attempt.
      }
    }
    setTarget(null);
    setMe(null);
    window.location.reload();
  }, [me]);

  const handleBack = useCallback(() => {
    setTarget(null);
    void loadHosts(filter);
  }, [filter, loadHosts]);

  if (target && me) {
    return (
      <TerminalView
        host={target.host}
        loginUser={target.loginUser}
        csrfToken={me.csrf_token ?? ""}
        onBack={handleBack}
      />
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <strong className="topbar__brand">Osmium</strong>
        {me ? (
          <>
            <span className="topbar__who">
              {(me.user.display_name || me.user.id) + (me.is_admin ? "（管理员）" : "")}
            </span>
            <button type="button" className="btn btn--compact" onClick={() => void handleLogout()}>
              退出登录
            </button>
          </>
        ) : null}
      </header>

      <main className="page-main">
        {authLoading ? (
          <p className="muted">正在检查登录状态…</p>
        ) : authError ? (
          <div className="banner banner--error" role="alert">
            {authError}
          </div>
        ) : !me ? (
          <LoginView />
        ) : (
          <HostsView
            hosts={hosts}
            loading={hostsLoading}
            error={hostsError}
            filter={filter}
            onFilterChange={setFilter}
            onRefresh={() => void loadHosts(filter)}
            onConnect={(host, loginUser) => setTarget({ host, loginUser })}
          />
        )}
      </main>
    </div>
  );
}
