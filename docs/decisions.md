# 默认决定、架构方向与未实现功能

[design/10-decisions-open-questions.md](design/10-decisions-open-questions.md) 中部分问题留给产品最终确认。**在得到明确产品拍板前，下表严格区分“用户明确需求”“当前实现基线”与“待确认决定”，不得将建议内容视为用户已最终承诺的产品决定。**

## 用户最新明确方向（大规模单二进制演进）

- **设备规模与负载特征**：目标承载 **>50,000 台设备**，且平时 **99% 设备处于空闲态**（仅少量并发活跃 SSH 会话）。
- **部署形态**：优先**单二进制部署**（不强依赖外置数据库/缓存集群；服务端可选启用内嵌纯 Go SQLite WAL 持久化）。
- **Agent 通道形态**：同意放弃旧 ADR-04 的“控制 WSS + 独立常驻数据 WSS”双连接建议基线，改用**单条 mTLS WSS**（`/agent/v1/tunnel`，子协议 `web-ssh-tunnel.v2`），并在有活跃 SSH 时按需拉起/空闲自动休眠 `smux v2`。详细规格见 [protocol-single-wss.md](protocol-single-wss.md)。

## 当前实现基线（对应未决项）

| 编号 | 问题 | 当前实现基线 |
| --- | --- | --- |
| O01 | Server 能否看到明文 | Web 模式下能：Server 就是 SSH 客户端。原生模式下不能：Server 只做授权、签发短期证书并透传 SSH 字节 |
| O04 | 规模与多副本 | 当前面向单机单二进制承载 50,000+ 空闲设备设计：单条 mTLS WSS + 按需 `smux v2`、256 分片 Hub、建连限流、Agent 抗惊群抖动、异步批量审计、分页 API/UI、可选内嵌 SQLite (WAL) 持久化登录态/策略/审计索引。多副本集群路由尚未启用，但因已统一为单条 WSS 与 `Store` 抽象，后续可直接演进 |
| O05 | 60 秒的含义 | 按“签发后剩余约 60 秒”处理。step-ca 默认把 `valid_after` 往前回拨 1 分钟（`authority.backdate`），所以证书的总区间是 120 秒。已在真实 step-ca 0.30.2 上测得。若需更严格区间可在 CA 侧调小 `authority.backdate`（影响整个 CA） |
| O06 | 浏览器断开 | 立即关闭该会话，不支持重新 attach。Agent 隧道断开或保活超时会结束整个 epoch 及其活跃会话；空闲 `smux` 休眠不影响在线状态 |
| O07 | 撤销/禁用后如何处理 | 策略移除授权、管理员通过增量 API 修改/删除授权或将用户加入 `disabled_users` 后：立即拒绝新请求、清除被禁用用户的服务端 Web 会话与 CLI 令牌，并立即关闭其活跃会话（可通过 `sessions.revoke_active` 控制仅授权撤回是否踢活跃会话）。管理员也可通过 API 集中吊销单条 CLI 令牌或一键吊销指定用户的全部凭证与活跃会话 |
| — | 会话时长与空闲超时 | 证书过期不影响已建立的会话。最长时长由 `sessions.max_session_duration` 控制（示例 8 小时）；支持 `sessions.idle_timeout`（默认 0 关闭，示例 30 分钟）自动关闭长期空闲的 Web / 原生会话 |
| — | `sshd MaxStartups` 与 CA 并发保护 | 每 Agent 独立限制未认证 pending stream 数量（`max_pending_streams_per_agent`，默认 8，低于 OpenSSH 默认 `MaxStartups=10`），Server 全局限制并发 CA 签发数（`sessions.max_concurrent_signs`，默认 16），`step-ca` 客户端复用持久化 HTTP 连接池 |
| — | Agent 身份与冲突告警 | 用专用客户端 CA 做 mTLS，CN 映射到策略中的主机。同 CN 新连接会取代旧 epoch 并写入 `agent.superseded` 审计告警；Agent 支持通过 `GetClientCertificate` 无重启热重载轮换后的 mTLS 客户端证书 |
| — | 主机身份 | 同时支持**固定登记的 plain host key** 与 **SSH Host CA**（`host_ca_public_keys` + 主机 `host_cert_principals`，默认 `[host.id]`），Web 与原生模式均严格 fail-closed 校验 |
| — | 桌面 ssh-agent / 原生 OpenSSH | 已通过 `osmium ssh` 实现，见 [native-ssh.md](native-ssh.md)。创建与附着原生隧道均强制 CLI Bearer 认证。推荐配合 `web-user-loopback.tpl` 与 `ca.required_source_address` 限制证书仅允许从主机 loopback 认证，防止 60 秒证书在内网旁路直连 `sshd` |
| — | 审计 | 异步有界队列批量写入本地 JSONL 分段文件；启用 `state_db`（SQLite WAL）时同步建立本地索引支持毫秒级检索；配置 `audit.s3` 后封口分段 gzip 上传到 S3 兼容存储（AWS S3、MinIO、RustFS）。不做防篡改 |
| — | 前端依赖与列表渲染 | 使用 React + `ghostty-web`（WASM），由 Vite 本地打包并嵌入 Server 二进制（`web/dist`），禁止外部 CDN；主机目录与管理员 Agent 列表均使用服务端游标分页与搜索过滤 |

## 仍待产品确认的架构方向

1. **多副本高可用切换时机（O04 扩展）**：
   - 当前单机单二进制已能承载 50,000+ 空闲设备，但单机升级/故障仍有短时重启中断（设备在抖动窗口内平滑重连）。
   - 若未来需要零中断滚动升级或突破 100k+ 规模，可将 `state_db` 抽象扩展为外部 PostgreSQL + 节点间 owner 代理转发（保持单二进制多副本部署形态）。
2. **原生 SSH 模式与合规审计边界（O01）**：
   - 原生透传模式下 Server 看不到明文，且 OpenSSH 证书仅带 `permit-pty` **并不阻止 `exec`、多路复用 channel 或目标机已启用的 `sftp` 子系统**。
   - 若商业场景要求强制终端录像或彻底禁止文件传输/多 channel，需决策禁用原生透传模式，或改为 Server 端双段 SSH 代理（MITM）。
3. **IdP 组/离职同步实时性（O07）**：
   - OIDC `GroupsClaim` 在登录时写入 Web 会话与 CLI 令牌，直至过期或被管理员/策略禁用吊销。若组织仅通过 IdP 移出分组而不操作 Osmium，需确认可接受的失效窗口（缩短 `web_session_ttl`、接入 IdP 周期性 UserInfo/SCIM 同步，或结合 `disabled_users` / `/api/v1/admin/users/{id}/revoke` 联动）。
4. **单租户与多租户隔离（O08）**：
   - 当前策略与数据库仅支持单个顶层 `scope`，尚未实现完整多租户控制面与数据隔离。

## 尚未实现

- 多副本共享状态集群与跨副本 owner 代理转发（单二进制已通过单条 WSS 与存储抽象完成前置解耦）。
- 审计日志的防篡改（哈希链、签名或 Object Lock）。
- 审计写入失败时的 fail-closed 策略与本地缓冲目录磁盘配额保护。
- Agent mTLS 证书 CRL/OCSP 在线吊销检查（当前通过删除/禁用主机立即踢出在线连接并拒绝重连）。
- 完整管理后台 UI（目前提供管理员 API：主机/授权/Host CA 增量 CRUD、`/api/v1/admin/agents`、`/api/v1/admin/audit`、`/api/v1/admin/cli-tokens`、`POST /api/v1/admin/cli-tokens/{id}/revoke`、`POST /api/v1/admin/users/{id}/revoke`）与 Prometheus `/metrics`。
- 会话录制，以及显式受控的 SFTP / 端口转发产品能力。
- Windows 平台的原生 `osmium ssh` 客户端支持（当前依赖 Unix domain socket 与 POSIX `ProxyCommand`）。
