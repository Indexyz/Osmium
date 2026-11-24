# 单条 mTLS WSS 与大规模演进协议/接口规格（Phase 1–3）

> 状态边界声明：
> - **用户已明确需求**：Go 实现 Server/Gateway 与 Agent；Agent 主动 WebSocket 连接；sshd 反向转发通过 `github.com/xtaci/smux`（wire version 2）；短 TTL SSH 用户证书（step-ca）；目标承载 >50,000 台设备（99% 空闲）；优先单二进制部署；采用单条 mTLS WSS。
> - **本规格定义的建议基线**：帧复用编码（Text + 带 `mux_gen` 前缀的 Binary）、按需拉起与自动休眠 `smux`、WS Ping/Pong 保活、256 分片 Hub、内嵌纯 Go SQLite (WAL) 存储、分页/增量管理 API 与 SSH Host CA 校验。
> - **仍待产品最终确认**：[design/10-decisions-open-questions.md](design/10-decisions-open-questions.md) 中 O01、O02、O05、O06、O08 等业务语义项未在本规格中擅自锁死。

---

## 1. Phase 1：单条 mTLS WSS + 按需 `smux v2` 传输协议

### 1.1 通道与身份绑定

| 项目 | 规格 |
| --- | --- |
| 路径 | `GET /agent/v1/tunnel`（替代旧 `/agent/v1/control` + `/agent/v1/data` 双连接） |
| Subprotocol | `web-ssh-tunnel.v2` |
| 传输安全 | 强制 mTLS（TLS 1.2+，推荐 TLS 1.3 开启会话票据复用），禁用 WebSocket compression |
| 身份映射 | 由服务端校验客户端证书链并提取 CN 映射到可信策略中的 `host` 与 `agent_id`；不再需要一次性 `data_ticket` |
| 状态模型 | 完成 `agent.hello` → `agent.welcome` 即为 `ready`；彻底消除旧双连接的 `connecting` 半成品态 |

### 1.2 WebSocket 帧复用模型（`wsDemux`）

同一条 mTLS WSS 上通过 RFC 6455 原生帧类型隔离控制面、保活面与数据面：

```text
Agent ◀═══════════════ 单条 mTLS WSS (/agent/v1/tunnel) ═══════════════▶ Server
       ├── Ping / Pong (0x9 / 0xA)  : 低开销保活（默认 45s ± 抖动），服务端无锁更新 lastSeen
       ├── Text Frame  (0x1)        : 控制消息 JSON，单帧上限 64 KiB，严格 DisallowUnknownFields
       └── Binary Frame (0x2)       : [4B big-endian uint32 mux_gen][smux v2 字节]，单帧上限 128 KiB
```

1. **WebSocket ReadLimit**：外层连接显式设置 `SetReadLimit(128 KiB)`（禁止 `-1` 无界读），Text 帧额外检查 `<= 64 KiB`。
2. **绝不设置单会话外层 deadline**：底层 WebSocket 仅绑定整个 Agent epoch 的父 context；单会话建连/握手/空闲超时只作用于对应 `*smux.Stream` 或 SSH 层。
3. **单读循环 + 原子串行写**：
   - 双方每条 WSS 仅运行 **1 个常驻读协程**（空闲设备从旧架构 8 个 goroutine 降为 **1 个**）。
   - Text 帧发送（`SendText`）与 Binary 帧发送（`WriteBuffers`）共用同一写互斥锁，保证控制指令与后续数据帧在单 TCP 上严格保序。
4. **零拷贝 `WriteBuffers`**：`wsDemux` 提供给 `smux.Session` 的代次连接实现 `WriteBuffers(v [][]byte) (int, error)`，在单条 WS Binary 帧内直接写入 `[4B mux_gen] + v[0] + v[1] ...` 并返回 `sum(len(v[i]))`（不含 4B 前缀）。这使 `smux` 跳过 64 KiB `sendLoop` 固定缓冲分配并避免额外内存拷贝。

### 1.3 控制消息契约（Text Frame, JSON Envelope v1）

公共信封：`{"version":1,"type":"...","message_id":"m-...","payload":{...}}`。

| Type | 方向 | Payload 字段 | 说明 |
| --- | --- | --- | --- |
| `agent.hello` | Agent → Server | `agent_version`, `reported_labels` | 建连首帧，限时 `hello_timeout`（默认 10s）；`reported_labels` 仅展示不授权 |
| `agent.welcome` | Server → Agent | `agent_id`, `host_id`, `connection_epoch`, `tunnel_id`, `smux_version`(2), `ping_interval_ms`, `ping_timeout_ms` | 绑定身份与单调递增 `epoch`，下发保活参数；无 `data_ticket` |
| `mux.open` | Server → Agent | `connection_epoch`, `mux_gen`(uint32 ≥ 1), `smux`（`max_frame_size`, `max_receive_buffer`, `max_stream_buffer`, `keepalive_interval_ms`, `keepalive_timeout_ms`） | 按需激活 `smux v2` 会话；服务端统一下发合法有界 smux 参数 |
| `mux.close` | Server → Agent | `connection_epoch`, `mux_gen`, `reason` | 空闲回收或重置当前代次 `smux.Session`；**不关闭外层 WSS** |
| `session.close` | Server → Agent | `connection_epoch`, `session_id`, `attempt_id`, `reason` | 幂等取消指定 attempt 的 stream 与本机 TCP |
| `session.closed` | Agent → Server | `connection_epoch`, `session_id`, `attempt_id`, `reason` | 清理回执；不同 epoch 的回执被忽略 |

`smux` 参数安全边界（双端强制校验）：
- `max_frame_size`: `[1024, 32768]`（默认 `16384`）
- `max_receive_buffer`: `[65536, 16777216]`（默认 `4194304`）
- `max_stream_buffer`: `[16384, 4194304]`（默认 `262144`）
- `keepalive_interval_ms`: `[5000, 300000]`（默认 `30000`；外层已有 WS Ping/Pong，内层可放宽）
- `keepalive_timeout_ms`: `>= 2 * keepalive_interval_ms` 且 `<= 600000`（默认 `90000`）

### 1.4 按需拉起 / 自动休眠 `smux` 状态机与竞态证明

```mermaid
sequenceDiagram
    participant U as User/Sessions
    participant G as Gateway (Hub + wsDemux)
    participant A as Agent (wsDemux)
    participant S as Local sshd

    Note over G,A: 空闲态：仅 1 条 mTLS WSS，无 smux.Session，仅 WS Ping/Pong 保活
    U->>G: OpenStream(host, session, attempt)
    G->>G: gen = ++muxGen; Activate(gen); NewGatewayMux(genConn)
    G->>A: Text: mux.open{epoch, mux_gen=gen, smux}
    G->>A: Binary: [gen][smux SYN + ssh.open prelude] (0-RTT)
    Note over A: 单读循环先同步处理 Text(mux.open) 建立 smux.Server(gen)
    Note over A: 下一帧 Binary([gen]...) 立即交付给 smux.Server(gen)
    A->>S: TCP Dial 127.0.0.1:22
    A-->>G: Binary: [gen][ssh.open_result{ok:true}]
    Note over U,S: 证书签发 → SSH 握手 → 交互终端/原生隧道
    U->>G: 最后一个 stream 关闭
    Note over G: 启动 mux_idle_ttl 定时器（默认 60s）
    G->>A: Text: mux.close{epoch, mux_gen=gen, reason="idle"}
    G->>G: 关闭 smux.Session(gen) 与 genPipe，保留外层 WSS
    A->>A: 关闭 smux.Session(gen) 与 genPipe，保留外层 WSS
```

**竞态免疫规则**：
1. **关闭与重开交错**：若 Server 发出 `mux.close(gen=1)` 后很快又发出 `mux.open(gen=2)`，在途的 `Binary[gen=1]` 到达任一端时满足 `gen < activeGen`（或 `activePipe == nil && gen <= lastGen`），由 `wsDemux` 直接静默丢弃，不会污染 `gen=2` 的 smux 状态机。
2. **伪造/越界代次**：收到 `gen == 0` 或 `gen > lastGen`（未先经 `mux.open` 激活）的 Binary 帧一律视为协议违规，立刻关闭整条 WSS epoch。
3. **非预期方向开流**：Gateway 侧监督协程阻塞在 `mux.AcceptStream()`，一旦 Agent 侧违规向 Server 主动打开 stream，或当前代次出现 smux 协议错误，立即关闭整个 WSS epoch。
4. **撤权与拥塞兜底**：撤权时 Gateway 立刻关闭本地 `smux.Stream` 与用户侧连接（用户瞬间断连），再异步向 Agent 发送 `session.close`；若因 TCP 写队列拥塞导致发送超时（5s），直接终止该设备整个 WSS epoch，Agent 自动 `CloseAll()` 切断所有本机 sshd 连接。

### 1.5 50,000+ 设备规模控制（分片、限流与抗惊群）

1. **256 分片 Hub**：`Hub` 按 `fnv32a(agent_id) % 256` 分片加锁，消灭单一全局 `Hub.mu` 竞争；全局单调 `epoch` 使用 `atomic.Uint64`。
2. **全局单一保活巡检协程**：不再为每个设备分配逐帧 `context.WithTimeout`；`OnPingReceived` 与收到任意合法帧时无锁写入 `presence.lastSeen`（`atomic.Int64`），由 Hub 单个后台协程周期（`min(HeartbeatTimeout/4, 5s)`）扫描所有分片，超时即取消 epoch。
3. **建连令牌桶限流**：Server 端对 `/agent/v1/tunnel` 升级前施加令牌桶限流（可配置 `agent_accept_rate` 默认 4000/s，`agent_accept_burst` 默认 8000；0 表示不限流），超限返回 `503 Service Unavailable` + `Retry-After`。
4. **Agent 抗惊群退避**：稳定运行超过 2 分钟后断连，首次重连不再集中于 0.5–1s，而是在 `[0, reconnect_jitter]`（默认 `30s`）内均匀随机分散；连续失败采用 Full Jitter 指数退避至 `reconnect_max_backoff`（默认 `60s`）。

---

## 2. Phase 2：异步审计、无锁争用状态管理与全面分页 API

### 2.1 异步批量审计
- `audit.Record` 立即生成事件 ID 与 UTC 时间戳后投递至有界缓冲队列（默认 16,384 条），后台单写协程按批次（每 100ms 或 256 条）合并落盘（同步写入可选 SQLite 索引）。
- `Flush()` 提供写屏障，`Search()`、`Sync()`、`Close()` 均先 `Flush()` 保证读/关强一致；队列满时触发 `OnError(ErrQueueFull)`，不阻塞业务锁。
- 优雅关闭顺序：`hub.Shutdown()` → `hub.Wait(timeout)` → `webSrv.Shutdown` / `agentSrv.Shutdown` → `audit.Close()`。

### 2.2 会话、认证与 CA 客户端性能改造
- `sessions.Manager`：`admitLocked` 严禁持锁调用 `Hub.Status()` 或 `audit.Record()`；使用增量计数 `activeTotal` / `activePerUser` 将配额检查降为 $O(1)$；过期清理改为后台周期任务 + FIFO 容量淘汰。
- `authn.Authenticator`：移除登录/换 token 时的持锁全表扫描，改为后台周期清理 + FIFO 容量淘汰；支持接入持久化存储后端。
- `ca.StepCA`：显式配置 `http.Transport` 连接池（`MaxIdleConns: 128`, `MaxIdleConnsPerHost: 64`, `IdleConnTimeout: 90s`）。

### 2.3 分页查询接口规格（向后兼容）

* **`GET /api/v1/hosts`**
  * 查询参数：
    * `label=k=v`（可重复，AND）
    * `q=<keyword>`（匹配 `id` 或 `display_name`，不区分大小写）
    * `status=ready|offline|disabled`
    * `limit=1..500`（默认 `50`）
    * `cursor=<base64url(last_host_id)>`
  * 响应：`{"items":[...], "next_cursor":"...", "total": 1234}`（无下一页时省略 `next_cursor`）。
  * 服务端执行顺序：先筛出匹配当前用户 `Subject` 的 grants 子集 → 结合倒排标签索引与预排序主机表授权筛选 → 应用 `q`/`status` → 游标切片，并单次产出 `allowed_login_users`，消除重复计算。
* **`GET /api/v1/admin/agents`**
  * 查询参数：`q=<agent_id或host_id子串>`、`limit=1..1000`（默认 `100`）、`cursor=<base64url(last_agent_id)>`。
  * 响应：`{"items":[...], "next_cursor":"...", "total": 50000}`。
* **CLI 与 Web UI**：
  * CLI `osmium hosts` 支持 `--query/-q`、`--status`、`--limit`、`--all`；去掉 `4 MiB` 整包截断风险，按页自动拉取。
  * Web UI `HostsView` 改为服务端分页（上一页/下一页 + 总数显示 + 状态筛选 + 标签/关键字搜索）。

---

## 3. Phase 3：单二进制内嵌 SQLite (WAL)、增量管理 API、SSH Host CA 与证书热重载

### 3.1 内嵌纯 Go SQLite (WAL) 存储（`state_db`）
- Server 配置新增可选字段 `state_db`（路径，如 `/var/lib/osmium/osmium.db`）。使用纯 Go `modernc.org/sqlite`（`CGO_ENABLED=0`），保持单二进制部署且绝不进入 `osmium-agent` 依赖图。
- 持久化表：
  - `meta`（`scope` 等）
  - `hosts`、`host_labels`（复合索引 `(k, v, host_id)`）
  - `grants`、`admins`、`disabled_users`、`host_cas`
  - `web_sessions`、`cli_tokens`（重启不丢登录态与 CLI 令牌）
  - `audit_events`（带 `(ts, action, actor, user_lower, session_id, target)` 索引，由审计写协程微批落盘；启用 `state_db` 且未强制走远程 S3 全量扫描时可实现毫秒级审计检索）
- 兼容 `policy_file`：首次启动若 DB 为空且配置了 `policy_file`，自动导入；保留 `SIGHUP` 重新导入 `policy_file` 的兼容行为。

### 3.2 增量管理 API（管理员 + CSRF + 审计 + 精确影响范围推送）

| 方法与路径 | 说明 |
| --- | --- |
| `PUT /api/v1/admin/hosts/{host_id}` | 增量创建或更新单台主机；仅针对受影响 `host_id` 校验并断开禁用/换绑的 Agent epoch |
| `DELETE /api/v1/admin/hosts/{host_id}` | 删除主机并立即断开对应 Agent 与活跃会话 |
| `PUT /api/v1/admin/grants/{grant_id}` | 增量创建或更新单条授权规则，立即触发活跃会话复核 |
| `DELETE /api/v1/admin/grants/{grant_id}` | 删除授权规则并踢出失去权限的活跃会话 |
| `PUT /api/v1/admin/host-cas` | 设置/轮换全局信任的 SSH Host CA 公钥列表 |

### 3.3 SSH Host CA 校验（Web 与原生模式）
- 策略与 DB 新增顶层 `host_ca_public_keys: []string`；每台主机新增可选 `host_cert_principals: []string`（默认缺省为 `[host.ID]`）。
- 每台主机**必须**至少配置固定 `ssh_host_keys` 或全局已配置 `host_ca_public_keys`（fail-closed，不允许无校验主机）。
- **Web 模式**：`sshgateway.HostKeyCallback` 同时支持固定 plain host key 与 `*ssh.Certificate`（强校验 `CertType == ssh.HostCert`、签发 CA 在信任列表内、有效期与 `host_cert_principals` 精确匹配）。
- **原生模式**：`native.ready` 扩展可选字段 `host_cas` 与 `host_cert_principals`（`host_keys` 与 `host_cas` 至少存在其一），CLI 写入临时 `known_hosts`（`@cert-authority <principals> <ca_key>`）交由 OpenSSH 严格校验。

### 3.4 Agent mTLS 证书无中断热重载
- `osmium-agent` 使用 `tls.Config.GetClientCertificate` 按 `client_cert` / `client_key` 的文件 mtime 按需重载证书对；重载失败保留上次有效证书并输出错误日志，轮换证书无需重启进程。
