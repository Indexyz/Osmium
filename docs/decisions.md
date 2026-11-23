# 默认决定、架构方向与未实现功能

[design/10-decisions-open-questions.md](design/10-decisions-open-questions.md) 中部分问题留给产品最终确认。**在得到明确产品拍板前，下表仅代表当前实现基线，不得视为用户已最终承诺的产品决定。**

## 当前实现基线（对应未决项）

| 编号 | 问题 | 当前实现基线 |
| --- | --- | --- |
| O01 | Server 能否看到明文 | Web 模式下能：Server 就是 SSH 客户端。原生模式下不能：Server 只做授权、签发短期证书并透传 SSH 字节 |
| O04 | 多副本 | 当前为单副本，配置固定的 `server_id`。会话、登录态与 Agent 连接在内存中，重启后丢失（epoch 以毫秒时间戳初始化以避免跨重启审计碰撞） |
| O05 | 60 秒的含义 | 按“签发后剩余约 60 秒”处理。step-ca 默认把 `valid_after` 往前回拨 1 分钟（`authority.backdate`），所以证书的总区间是 120 秒。已在真实 step-ca 0.30.2 上测得。若需更严格区间可在 CA 侧调小 `authority.backdate`（影响整个 CA） |
| O06 | 浏览器断开 | 立即关闭该会话，不支持重新 attach。control 或 data 任一通道断开（或控制通道在 ticket 过期后迟迟未建立数据通道），都会结束整个 epoch 及其会话 |
| O07 | 撤销/禁用后如何处理 | 策略移除授权或将用户加入 `disabled_users` 并 `SIGHUP` 热加载后：立即拒绝新请求、清除被禁用用户的服务端 Web 会话与 CLI 令牌，并立即关闭其活跃会话（可通过 `sessions.revoke_active` 控制仅授权撤回是否踢活跃会话）。管理员也可通过 API 集中吊销单条 CLI 令牌或一键吊销指定用户的全部凭证与活跃会话 |
| — | 会话时长与空闲超时 | 证书过期不影响已建立的会话。最长时长由 `sessions.max_session_duration` 控制（示例 8 小时）；支持 `sessions.idle_timeout`（默认 0 关闭，示例 30 分钟）自动关闭长期空闲的 Web / 原生会话 |
| — | `sshd MaxStartups` 与 CA 并发保护 | 每 Agent 独立限制未认证 pending stream 数量（`max_pending_streams_per_agent`，默认 8，低于 OpenSSH 默认 `MaxStartups=10`），Server 全局限制并发 CA 签发数（`sessions.max_concurrent_signs`，默认 16） |
| — | Agent 身份与冲突告警 | 用专用客户端 CA 做 mTLS，CN 映射到策略中的主机。同 CN 新连接会取代旧 epoch 并写入 `agent.superseded` 审计告警，便于排查克隆镜像或凭据滥用 |
| — | 主机身份 | 只支持登记固定的 host key，尚未支持 host CA |
| — | 桌面 ssh-agent / 原生 OpenSSH | 已通过 `osmium ssh` 实现，见 [native-ssh.md](native-ssh.md)。创建与附着原生隧道均强制 CLI Bearer 认证。推荐配合 `web-user-loopback.tpl` 与 `ca.required_source_address` 限制证书仅允许从主机 loopback 认证，防止 60 秒证书在内网旁路直连 `sshd` |
| — | 审计 | 参考 Teleport 审计日志：事件追加写入本地分段文件；配置 `audit.s3` 后，封口分段 gzip 上传到 S3 兼容存储（AWS S3、MinIO、RustFS），过期清理使用批量删除。管理员通过 `GET /api/v1/admin/audit` 查询。不做防篡改 |
| — | 前端依赖 | 使用 React + `ghostty-web`（WASM），由 Vite 本地打包并嵌入 Server 二进制（`web/dist`），不再依赖外部 CDN，支持离线部署 |

## 需要尽早拍板的架构方向（待确认）

1. **多副本与控制/数据通道形态（O04）**：
   - 当前建议基线采用“控制 WSS + 独立数据 WSS”双连接模型（ADR-04），适合单副本；但进入多副本 + 标准负载均衡器场景时，同一 Agent 的两条独立升级请求可能落到不同副本。
   - 演进到多副本前，需在以下两条路线中明确抉择（当前均未锁定）：
     - **方案 A（保留双 WSS）**：在 `agent.welcome` 中下发可路由至 owner 副本的定向端点/路由提示，或由非 owner 副本在集群内代理转发至 owner，并引入共享持久化存储与跨副本事件总线；
     - **方案 B（合并为单 mTLS WSS + smux 控制流）**：在单条 mTLS WSS 上直接运行 `smux v2`，由第一条专用高优先级 stream 承载控制消息。可省去一次性 `data_ticket`、消除跨副本双连接路由错位与 `connecting` 半成品态，并减半边缘设备连接数。
2. **原生 SSH 模式与合规审计边界（O01）**：
   - 原生透传模式下 Server 看不到明文，且 OpenSSH 证书仅带 `permit-pty` **并不阻止 `exec`、多路复用 channel 或目标机已启用的 `sftp` 子系统**。
   - 若商业场景要求强制终端录像或彻底禁止文件传输/多 channel，需决策禁用原生透传模式，或改为 Server 端双段 SSH 代理（MITM）。
3. **IdP 组/离职同步实时性（O07）**：
   - OIDC `GroupsClaim` 在登录时写入 Web 会话与 CLI 令牌，直至过期或被管理员/策略禁用吊销。若组织仅通过 IdP 移出分组而不操作 Osmium，需确认可接受的失效窗口（缩短 `web_session_ttl`、接入 IdP 周期性 UserInfo/SCIM 同步，或结合 `disabled_users` / `/api/v1/admin/users/{id}/revoke` 联动）。
4. **单租户与多租户隔离（O08）**：
   - 当前策略文件仅支持单个顶层 `scope`，尚未实现完整多租户控制面与数据隔离。

## 尚未实现

- 会话状态与令牌的持久化、多副本部署与 owner 路由（审计已可通过 S3 共享并按 `server_id` 区分）。
- 审计日志的防篡改（哈希链、签名或 Object Lock）与全文检索/分析查询。
- 审计写入失败时的 fail-closed 策略与本地缓冲目录磁盘配额保护。
- SSH host CA 校验、Agent mTLS 证书无中断热轮换与 CRL/OCSP 检查。
- 管理 UI（目前提供管理员 API：`/api/v1/admin/agents`、`/api/v1/admin/audit`、`/api/v1/admin/cli-tokens`、`POST /api/v1/admin/cli-tokens/{id}/revoke`、`POST /api/v1/admin/users/{id}/revoke`）与 Prometheus `/metrics`。
- 会话录制，以及显式受控的 SFTP / 端口转发产品能力。
- Windows 平台的原生 `osmium ssh` 客户端支持（当前依赖 Unix domain socket 与 POSIX `ProxyCommand`）。
