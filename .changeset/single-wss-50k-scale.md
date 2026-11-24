---
"osmium": minor
---

面向 >50,000 台设备（99% 空闲）与单二进制部署架构升级（Phase 1–3）：

- **单条 mTLS WSS + 按需 `smux v2`（`web-ssh-tunnel.v2`）**：合并旧控制/数据双连接为单条 `/agent/v1/tunnel`，通过 `wsDemux` 分帧复用 Text 控制帧、WS 原生 Ping/Pong 保活与带 `4B mux_gen` 前缀的按需 Binary `smux v2` 帧；支持 0-RTT 激活、空闲自动休眠回收与零拷贝 `WriteBuffers`，移除 `data_ticket`。
- **256 分片 Agent Hub 与抗惊群护栏**：按 `agent_id` 256 分片加锁、单协程无锁心跳巡检、接入令牌桶限流（超限 503），以及 Agent 断连随机抖动重连与 `GetClientCertificate` mTLS 证书无重启热重载。
- **异步批量审计、无锁争用状态与全链路游标分页**：审计写入改为有界异步队列批量落盘；消除 `sessions`/`authn` 持锁全表扫描与锁内 I/O；调大 `step-ca` HTTP 连接池；`authz` 引入倒排标签索引与预排序主机表；`/api/v1/hosts`、`/api/v1/admin/agents`、CLI 与 Web UI 全面支持游标分页与关键字/标签/状态过滤。
- **单二进制内嵌 SQLite (WAL)、增量管理 API 与 SSH Host CA**：可选启用纯 Go `modernc.org/sqlite`（`state_db`，严格排除在 `osmium-agent` 之外）持久化主机/策略/Host CA、Web 会话、CLI 令牌与审计索引；新增主机/授权/Host CA 管理员增量 CRUD API；Web 与原生 OpenSSH 模式均支持 SSH Host CA 校验。
