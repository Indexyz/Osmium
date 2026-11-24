# Changelog

## 0.2.0

### Minor Changes

- [`347810f`](https://github.com/Indexyz/Osmium/commit/347810ffcf9c910c8f1b4a13f073c32052af9e96) Thanks [@5aaee9](https://github.com/5aaee9)! - 新增无 Agent 直连 Zero Trust SSH 证书签发与内置本地只读 `osmium ssh-agent`：

  - **策略、SQLite 持久化与独立 `direct_ca` 签发**：主机新增 `connection_mode`（`tunnel` / `direct` / `both`）与 `ssh_address`；新增 `cert_roles` 角色/组级多主机 principal 与 TTL/扩展策略（含 SQLite `state_db` 自动迁移与管理员增量 API `GET/PUT/DELETE /api/v1/admin/cert-roles/{role_id}`）；Server 新增独立 `direct_ca` 配置段与 `POST /api/v1/direct-certs`（仅限 CLI Bearer、临时公钥一次性防重放、签发后二次复核，并支持 `none` / `static` / `client_ip` + `trusted_proxies` 可选 `source-address` 限制）及 `GET /api/v1/host-cas`。
  - **CLI 直连工作流与原生 OpenSSH 集成**：`osmium ssh` 自动识别直连/离线回退主机（支持 `--direct` 与跨平台直连，不再依赖隧道 `ProxyCommand`）；新增 `osmium cert login|sign|ensure` 与 `osmium ssh-config`（生成 `Match exec` 或 `--use-agent` + `@cert-authority` `known_hosts`，原生支持 `ssh`/`scp`/`rsync`/VS Code Remote-SSH/Ansible）。
  - **内置常驻只读 `osmium ssh-agent`**：本地 OpenSSH Agent 守护进程，临时私钥与证书仅存内存不落盘、拒绝外部 `ssh-add`/删除/锁定、到期前自动轮换全新 Ed25519 密钥续签，探测到吊销或禁用（`401`/`403`）及进程退出时立即清零内存私钥。
  - **Web UI 与模板文档**：主机列表支持 `direct` 状态筛选与展示（仅 CLI 直连主机禁用浏览器终端连接以避免 SSRF）；补充直连 `step-ca` / `sshd` 配置模板与 [docs/direct-ssh.md](docs/direct-ssh.md)。

- [`15f4513`](https://github.com/Indexyz/Osmium/commit/15f4513c144071bb150a8cad46f062d72328fdde) Thanks [@5aaee9](https://github.com/5aaee9)! - 面向 >50,000 台设备（99% 空闲）与单二进制部署架构升级（Phase 1–3）：

  - **单条 mTLS WSS + 按需 `smux v2`（`web-ssh-tunnel.v2`）**：合并旧控制/数据双连接为单条 `/agent/v1/tunnel`，通过 `wsDemux` 分帧复用 Text 控制帧、WS 原生 Ping/Pong 保活与带 `4B mux_gen` 前缀的按需 Binary `smux v2` 帧；支持 0-RTT 激活、空闲自动休眠回收与零拷贝 `WriteBuffers`，移除 `data_ticket`。
  - **256 分片 Agent Hub 与抗惊群护栏**：按 `agent_id` 256 分片加锁、单协程无锁心跳巡检、接入令牌桶限流（超限 503），以及 Agent 断连随机抖动重连与 `GetClientCertificate` mTLS 证书无重启热重载。
  - **异步批量审计、无锁争用状态与全链路游标分页**：审计写入改为有界异步队列批量落盘；消除 `sessions`/`authn` 持锁全表扫描与锁内 I/O；调大 `step-ca` HTTP 连接池；`authz` 引入倒排标签索引与预排序主机表；`/api/v1/hosts`、`/api/v1/admin/agents`、CLI 与 Web UI 全面支持游标分页与关键字/标签/状态过滤。
  - **单二进制内嵌 SQLite (WAL)、增量管理 API 与 SSH Host CA**：可选启用纯 Go `modernc.org/sqlite`（`state_db`，严格排除在 `osmium-agent` 之外）持久化主机/策略/Host CA、Web 会话、CLI 令牌与审计索引；新增主机/授权/Host CA 管理员增量 CRUD API；Web 与原生 OpenSSH 模式均支持 SSH Host CA 校验。

All notable changes to Osmium are tracked with [Changesets](https://changesets.dev/).

## 0.1.0

### Initial Release

- Web SSH 访问系统：OIDC 登录、策略驱动授权、step-ca 短期 SSH 用户证书签发、Host Key Pinning 与结构化审计（本地 JSONL 分段 + S3 兼容存储归档）。
- 主机反向隧道 Agent：mTLS 控制通道 + `smux v2` 常驻数据通道，提供面向边缘设备的独立轻量二进制 `osmium-agent`。
- 原生 OpenSSH 客户端接入（`osmium login` / `osmium hosts` / `osmium ssh`）与限时 `ssh-agent` 集成。
- Web 终端迁移至 React + TypeScript + `ghostty-web`（WASM），本地打包嵌入二进制，移除外部 CDN 依赖。
- 安全与稳定性护栏：策略级 `disabled_users`、管理员 CLI 令牌与用户集中吊销 API、未认证 pending stream 与 CA 并发签发限流、会话空闲超时、可选 `source-address` loopback 证书模板及 `/healthz` 健康检查。
