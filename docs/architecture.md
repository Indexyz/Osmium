# 架构

```
浏览器 ──HTTPS/WSS──┐
                    ├─▶ Server（Web API + SSH Gateway + Direct Cert CA + 256 分片 Agent Hub + 内嵌 SQLite WAL）──HTTPS──▶ step-ca
osmium CLI /        │          ▲
osmium ssh-agent ───┘          │ 单条 mTLS WSS（/agent/v1/tunnel, web-ssh-tunnel.v2）
       │                       │ • 空闲态：WS Ping/Pong + Text 控制帧（无 smux 常驻开销）
       │                       │ • 活跃态：按需拉起 Binary [4B mux_gen][smux v2]（空闲自动休眠）
       │                       │
       │                    Agent ──TCP──▶ 127.0.0.1:22（NAT/受限主机 sshd）
       │
       └────────── 直连 TCP SSH（短期用户证书 + Host CA 校验）──────────▶ 无 Agent 普通 sshd
```

详细协议与大规模规格见 [protocol-single-wss.md](protocol-single-wss.md)（单条 WSS + 按需 smux + 分页/持久化/Host CA）以及历史设计交接文档 [design/02-architecture.md](design/02-architecture.md) 和 [design/05-protocols.md](design/05-protocols.md)。

## 组件

- **Agent** 运行在目标主机上，主动连出到 Server，仅维持**一条 mTLS WebSocket 长连接**（`/agent/v1/tunnel`）：
  - **空闲态**：不创建 `smux.Session`，仅通过 WebSocket 原生 Ping/Pong 保活与 Text 帧接收控制指令，极大降低 50,000+ 台设备（99% 空闲）场景下的内存、FD 与 goroutine 开销；
  - **活跃态**：收到 Server 的 `mux.open` 后按需建立 `smux v2`（通过 4 字节 `mux_gen` 前缀防代次竞态，并支持 `WriteBuffers` 零拷贝），空闲超时后由 Server 下发 `mux.close` 自动回收，外层 WSS 保持常驻；
  - 支持断连随机抖动防惊群与客户端 mTLS 证书无重启热重载；
  - Agent 只把 stream 转发到本机配置的 loopback sshd，不会连接任意地址。
- **stream**：每次 SSH 连接尝试独占一个 smux stream。
  - stream 开头是带长度前缀的 JSON prelude（`ssh.open` / `ssh.open_result`），确认之后只传原始 SSH 字节；
  - 关闭某个会话只关它自己的 stream，不会关闭共享的 `smux.Session` 或外层 WSS。
- **Server** 有两种会话模式：
  - **Web 模式**：Server 本身就是 SSH 客户端。每次尝试都会：
    1. 生成一次性的 ed25519 密钥；
    2. 按需激活目标 Agent 的 `smux v2` 并打开 stream，Agent 确认拨通 sshd 后，向 step-ca 申请签发短期证书，principal 为 `tenant:<scope>:host:<id>:login:<user>`；
    3. 校验返回的证书；
    4. 使用登记的固定主机公钥或信任的 **SSH Host CA**（校验签名、有效期与主机 principal）严格验证目标主机身份，然后建立 PTY shell，通过 React + Ghostty（`ghostty-web` WASM）呈现给浏览器。
  - **原生隧道模式**：用户本机的 OpenSSH 客户端与 NAT 后 sshd 端到端通信，Server 只做授权、签发证书、下发固定 host key / Host CA 与字节转发，看不到明文。见 [native-ssh.md](native-ssh.md)。
  - **无 Agent 直连模式**：针对网络可达的普通 `sshd` 服务器，Server 通过独立 `direct_ca` provisioner 签发单主机短期证书（默认 60s）或角色/组级中短期证书（如 1h–8h，经 `cert_roles` 授权与封顶，并支持可选 `source-address` 限制）。CLI 提供 `osmium ssh` 自动直连、`osmium cert`、`osmium ssh-config` 与内置只读常驻 `osmium ssh-agent`（内存持有、自动轮换密钥、吊销秒清）。见 [direct-ssh.md](direct-ssh.md)。
- **授权与持久化**完全在服务端（[design/03-authorization.md](design/03-authorization.md)）：
  - 支持可选内嵌纯 Go SQLite（WAL 模式，`state_db`）单二进制持久化主机、标签、授权、Host CA、Web 会话、CLI 令牌与审计索引，同时保留 `policy_file` 兼容导入与 `SIGHUP` 重载；
  - 提供管理员增量 API（主机/授权/Host CA 增删改），变更仅精确影响相关主机，无需全量扫描；
  - 客户端只能提交 `host_id`、`login_user`、终端尺寸，原生模式下再加一把公钥；principal、TTL、标签和 CA 参数都由服务端决定；Agent 上报的标签只用于展示；
  - 支持策略级 `disabled_users`（优先于 `admins` 与 `grants`）及管理员集中吊销 API（清除 Web 会话、CLI 令牌并关闭活跃 SSH 会话）。
- **复核与大规模稳定性护栏**：
  - 创建会话、打开 stream、签发证书、激活四个时刻均基于单次原子策略快照重新检查授权；
  - `Hub` 采用 **256 分片** + 全局单一保活巡检协程 + 接入令牌桶限流；
  - 每 Agent 独立限制未认证 `pending` stream 配额（`max_pending_streams_per_agent`，保护 `sshd MaxStartups`），Server 全局限制并发 CA 签发数（`sessions.max_concurrent_signs`）并复用 `step-ca` HTTP 连接池；
  - `/api/v1/hosts` 与 `/api/v1/admin/agents` 全面支持游标分页与服务端过滤，审计写入采用有界异步队列批量落盘。

## 会话状态

`created → waiting_agent → signing → ssh_authenticating → active → closing → closed`，任一步失败进入 `failed`。

原生模式没有 `ssh_authenticating`，因为 Server 看不到认证过程。见 [design/diagrams/session-state.mmd](design/diagrams/session-state.mmd)。

## 代码目录

| 路径 | 内容 |
| --- | --- |
| `cmd/osmium` | 主程序（cobra）：`server`、`agent`、`login`、`hosts`、`ssh`、`dev pki` 等 |
| `cmd/osmium-agent` | 目标主机上的独立 Agent，零重依赖（不含 SQLite/cobra/ssh/regexp），面向边缘设备 |
| `internal/tunnel` | `wsDemux` 单连接帧复用、按需 `smux v2` 传输层、prelude 编解码、Agent 端 stream 处理 |
| `internal/protocol` | 单 WSS 控制消息（`mux.open`/`mux.close`/`session.close`）、终端和原生隧道消息 |
| `internal/agenthub` | 256 分片 Agent 注册表、epoch、按需 smux 生命周期、保活巡检、接入限流与 stream 分配 |
| `internal/storage` | 单二进制内嵌纯 Go SQLite (WAL) 持久化存储（主机/策略/Host CA/登录态/审计索引） |
| `internal/ca` | step-ca JWK provisioner 客户端（连接池调优）和证书校验；`catest` 为测试用的假 CA |
| `internal/sshgateway` | Web 模式的 SSH 客户端（临时密钥、固定 host key + SSH Host CA 校验） |
| `internal/sessions` | 会话状态机（Web / 原生）、O(1) 并发配额与多次授权复核 |
| `internal/authz` | 策略、倒排索引、分页可见主机筛选、增量更新与 Host CA 校验元数据 |
| `internal/authn` | OIDC 登录、Web 会话、CLI 登录与 Bearer 令牌（支持持久化后端） |
| `internal/server` | HTTP API（含分页与管理员增量 CRUD）、终端 WebSocket 和原生隧道 |
| `internal/audit` | 异步批量审计：本地 JSONL 分段、可选 SQLite 索引与 S3 兼容存储归档 |
| `internal/client` | CLI 客户端：登录、分页主机列表、调用本机 ssh（支持固定 key 与 Host CA） |
| `internal/e2e` | 端到端测试（真实 sshd / ssh / ssh-agent，可选真实 step-ca） |
| `web/` | 前端（React + TypeScript + `ghostty-web`，分页目录，Vite 构建产物嵌入 `web/dist`） |
| `examples/` | 配置示例 |
