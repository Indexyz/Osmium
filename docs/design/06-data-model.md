# 06 数据模型与一致性（建议）

本章描述逻辑实体，不锁定数据库或 ORM。scope/tenant 字段为隔离预留；是否完整多租户待确认。

| 实体 | 建议字段 | 约束 |
|---|---|---|
| User | id, oidc_issuer, oidc_subject, display_name, disabled | `(issuer, subject)` 唯一；email 不作唯一安全身份 |
| Host | id, scope_id, display_name, policy_labels, ssh_host_identity, allowed_login_users, disabled | ID 稳定；关键字段修改审计 |
| Agent | id, host_id, credential_identity, credential_status, version | host 与凭据绑定明确；注册不可自选他人身份 |
| AgentPresence | agent_id, owner_server_id, connection_epoch, data_tunnel_id, data_ready, lease_expires_at, reported_labels | 短期运行态；租约/epoch 防旧 owner |
| AccessGrant | id, subject_selector, host_selector, allowed_login_users, actions, revision | label 仅使用可信 policy_labels |
| SSHSession | id, user_id, host_id, login_user, state, state_version, owner_server_id, policy_revision, created_at, activated_at, ended_at, end_reason | 每次转换并发保护；无私钥/OTT |
| ConnectionAttempt | id, session_id, agent_id, connection_epoch, data_tunnel_id, smux_stream_id, cert_serial, cert_key_id, public_key_fingerprint, valid_after, valid_before | 一次尝试一密钥；记录足够审计信息 |
| DataTunnelTicket | digest, agent_id, host_id, owner_server_id, connection_epoch, data_tunnel_id, expires_at, consumed_at | 仅一次共享数据 WSS 接入；不绑定单个 SSH session；原子消费 |
| AuditEvent | id, timestamp, actor, action, result, target, session_id, attempt_id, policy_revision, reason | 追加记录；访问限制与保留期待确认 |

## 权限与会话竞争

创建会话时记录已评估策略版本；签发前以及开放 PTY/shell 前重新校验当前权限和 cancellation。不能把创建时版本当作永远有效的快照。

撤销事件应能找到受影响的 active/pending 会话；owner 收到后幂等关闭并回报。跨副本传播失败需要可观察的 `closing/pending_revoke` 操作状态，不能先向管理员宣称已踢出而 socket 仍活跃。是否采用周期性重验、事件总线或两者结合待部署范围确定。

## owner 与 epoch

Agent 重新注册得到新 epoch；旧控制连接上的命令/回执不能修改新 epoch 下的会话。隧道 ticket 绑定 agent epoch 与 data_tunnel_id；每个 stream 的 open 报头绑定 host/epoch/session/attempt。smux stream ID 只在所属 Session 内有意义，不作为全局业务主键或秘密。只有拥有对应 owner lease 的进程可创建本次通道；失去 owner 身份后应停止接新连接，并按既定关闭策略处理现存会话。

数据库恢复 active 记录不等于恢复 SSH 连接。启动 reconcile 应将不存在实际 owner/socket 的记录标记为失联/失败，不能显示为仍可操作。

## 持久化禁止项

不存 SSH 临时私钥、明文 JWK 私钥、OIDC refresh token 到普通业务表或日志；如需保管凭据，应使用单独受保护的 secret 存储并进行权限分离。终端内容记录是单独产品能力，不与基本元数据审计混为一谈。
