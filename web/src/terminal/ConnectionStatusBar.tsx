import { sessionStatusView, type SessionStatus } from "./sessionState";

interface Props {
  targetLabel: string;
  hostId: string;
  status: SessionStatus;
  canDisconnect: boolean;
  canReconnect: boolean;
  onDisconnect(): void;
  onReconnect(): void;
  onBack(): void;
}

export default function ConnectionStatusBar({
  targetLabel,
  hostId,
  status,
  canDisconnect,
  canReconnect,
  onDisconnect,
  onReconnect,
  onBack,
}: Props) {
  const view = sessionStatusView(status);

  return (
    <div
      className="status"
      role="status"
      aria-live="polite"
      data-phase={status.phase}
      data-tone={view.tone}
      data-backend-state={status.backendState}
    >
      <div className="status__left">
        <span className="status__indicator" aria-hidden="true" />
        <span className="status__target" title={hostId}>
          {targetLabel}
        </span>
        <span className="status__separator">{" · "}</span>
        <span className="status__primary">{view.primary}</span>
        {view.detail ? (
          <>
            <span className="status__separator">{" · "}</span>
            <span className="status__detail">{view.detail}</span>
          </>
        ) : null}
      </div>

      <div className="status__actions">
        {canDisconnect ? (
          <button type="button" className="btn btn--danger btn--compact" onClick={onDisconnect}>
            断开
          </button>
        ) : null}
        {canReconnect ? (
          <button type="button" className="btn btn--primary btn--compact" onClick={onReconnect}>
            重新连接
          </button>
        ) : null}
        <button type="button" className="btn btn--compact" onClick={onBack}>
          返回主机列表
        </button>
      </div>
    </div>
  );
}
