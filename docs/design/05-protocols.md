# 05 协议契约 v0.2：WebSocket + smux

本章是新系统的建议契约，不是上游标准。HTTP API 版本与下列 wire version 独立；此版文档为 0.2，业务消息 version 为 1，smux wire version 显式为 2。

## 1. 通道

| 通道 | 路径 | 身份验证 | 内容 |
|---|---|---|---|
| HTTP API | `/api/v1/...` | 同源 Web session + CSRF | JSON |
| 浏览器终端 | `/api/v1/ssh-sessions/{session_id}/terminal` | session + ownership + Origin | binary 终端字节，text 控制 JSON |
| Agent 控制 | `/agent/v1/control` | 独立 Agent mTLS 身份（建议） | text 控制 JSON |
| Agent 数据 | `/agent/v1/data` | 同一机器身份 + 隧道一次性 ticket | binary，内层为 smux v2 |

subprotocol 分别为 `web-ssh-terminal.v1`、`web-ssh-control.v1`、`web-ssh-data.v1`。外部连接均为 WSS；控制与数据建议关闭 WebSocket compression。证书代理终止 TLS 时须严格定义身份传递的可信边界。

**不再使用 `/agent/v1/sessions/{id}/data`；没有逐 SSH 会话的数据 WebSocket。** 控制与数据 WSS 建好后复用，新增 SSH 仅打开 stream。

## 2. 控制消息

共同信封：`version、type、message_id、payload`。消息 schema 见 `api/control.schema.json`。

| 消息 | 方向 | 用途 |
|---|---|---|
| agent.hello | Agent → Server | Agent 软件版本、reported_labels；身份仍来自 mTLS |
| agent.welcome | Server → Agent | 绑定 agent/host/epoch、data_tunnel_id、短期 ticket、配置版本 |
| agent.heartbeat | Agent → Server | 对应 epoch 的状态心跳；不携带授权 label |
| agent.data_ready | Server → Agent | ticket 消费后数据 Session 已安装至路由表 |
| session.close | Server → Agent | 关闭匹配 epoch/session/attempt 的 stream/TCP；幂等 |
| session.closed | Agent → Server | 清理确认；不能改写不同 epoch 会话 |

不再定义控制通道 `session.open`：**smux stream 的 open 报头本身就是建连命令**，避免控制/数据两条连接的先后顺序竞争。关闭需要 context/registry 同时处理处于 dial/ack/copy 阶段的任务。

## 3. 共享数据隧道绑定

Server 在 welcome 中发送随机 opaque ticket。ticket 仅在内存/控制 WSS 明文出现，持久化仅摘要；绑定 `agent_id、host_id、owner_server_id、connection_epoch、data_tunnel_id、expires_at`。

Agent 在数据 Upgrade 时使用 `Authorization: Bearer <ticket>`，不放 query string。Server 校验 mTLS 身份、全部绑定、期限和当前 owner，然后原子消费。并发重放至多一个成功；失败后不把 ticket 恢复成未使用状态。ticket 不能当 SSH 证书或 OIDC token。

建议 ticket 30 秒过期，仅用于一次长期数据连接的建立。ticket 过期不终止已建立数据隧道，后续 stream 使用既有认证绑定；60 秒用户证书与它无关。

数据 Session 中的每个 stream 均受已认证 Agent/host/epoch 限制；不能通过报头换绑 host。Gateway 必须在打开每条流前完成用户授权。不要把 smux stream ID 当作权限凭据。

## 4. smux 角色与参数

Gateway：`smux.Client(websocket.NetConn(ctx, ws, websocket.MessageBinary), cfg)`。
Agent：`smux.Server(...)`，循环 `AcceptStream`。`cfg.Version = 2`；模块路径为 `github.com/xtaci/smux`。[S22][S23]

建议实验起点（非生产容量承诺）：

| 参数 | 值 | 含义 |
|---|---:|---|
| Version | 2 | 双端必须一致，不假定自动协商 |
| MaxFrameSize | 16 KiB | smux 数据帧上限，不是 WS message 上限 |
| MaxReceiveBuffer | 4 MiB | 每个 smux Session 的接收预算 |
| MaxStreamBuffer | 256 KiB | 每条流窗口/缓冲参数 |
| KeepAliveInterval / Timeout | 10s / 30s | 隧道保活；独立于交互空闲超时 |
| 每 Agent active + pending streams | 32 | 应用显式准入配额，非 smux 自带授权限制 |

每个 Session 的缓冲设置不包括所有 Go 对象、TCP/TLS、SSH 和浏览器输出队列；内存预算应按 Agent 数量和并发流压测。版本 2 的逐流流控不消除底层单 TCP 连接的队头阻塞；单流超大持续输出也应测试对其他流的影响。[S22]

## 5. 每条 stream 的 open/ack

双方先各发一条业务报头，格式为：

```text
uint32 big-endian JSON字节长度 N | 恰好 N 个 UTF-8 JSON 字节
1 <= N <= 16,384
```

Gateway → Agent 的报头示例：

```json
{"version":1,"type":"ssh.open","host_id":"host-123","session_id":"s789","attempt_id":"a001","connection_epoch":7}
```

Agent 校验消息、当前绑定、取消状态、重复 attempt、并发配额；只拨其本地受保护配置的 TCP 目标，不接受地址或端口字段。成功后回：

```json
{"version":1,"type":"ssh.open_result","session_id":"s789","attempt_id":"a001","ok":true}
```

失败回 `ok:false` 和稳定 `code`，然后关闭该 stream。建议代码：`OPEN_DENIED、INVALID_OPEN、STALE_EPOCH、HOST_MISMATCH、DUPLICATE_ATTEMPT、TOO_MANY_STREAMS、SSH_DIAL_FAILED、CANCELLED`。不得把敏感内部拨号错误写入公共 message。

ack 成功后，**两个方向均永久切换为原始 SSH 字节流**，不再解析 JSON；Gateway 此时才申请用户证书。用 `io.ReadFull` 读取精确长度，不可让 `json.Decoder` 直接从无限 stream 读取而吞掉后续 SSH banner。示例见 `reference/go/wire.go`。

每条流建连握手建议 10 秒上限、TCP dial 5 秒；参数待环境验证。报头或 ack 不合规关闭该 stream，反复违规可以升级为隧道级处罚。

## 6. lifecycle、超时与关闭

**两层 context：** 数据 WSS/smux Session 的父 context 属于机器隧道；每条 SSH stream/transport 有独立子 context。单个浏览器或会话 context 不能拿来创建整个 `websocket.NetConn`。[S12][S25]

Open/ack 与 SSH 握手期限只设在具体 stream。开始 relay/完成 SSH 握手后清除阶段性 deadline。不要在外层 NetConn 上设置某条 SSH 的 60 秒 deadline；底层关闭会结束全部 streams。

`Session.SetDeadline` 不是所有流的超时；不要用它替代 stream deadline。`OpenStream` 本身没有 context 参数；应保留其库级失败语义、限制 pending opens，不通过关闭整个 Session 来取消单次 OpenStream。[S22][S23]

正常 EOF 使用 `CloseWrite` 将 FIN 传播给对端，并等待反向末尾输出；提供有界 drain。错误或管理员取消执行 full-close。锁定的 smux v1.5.57 已有 `Stream.CloseWrite`，不能继续沿用“smux 不支持 half-close”的旧假设。[S24]

SSH channel EOF 不等于 smux FIN：前者属于 SSH 协议内的 shell/exec，后者属于整个 SSH transport 的字节流关闭。不能在某个 SSH channel 结束时错误截断仍使用同 transport 的其他 channel；MVP 建议一 transport 一 PTY，仍要按层清理。

Agent 维护 `(epoch,session_id,attempt_id) → cancel + TCP + stream` 注册表，关闭请求幂等。握手前、dial 中、ack 后都必须能取消。共享 data WSS 失败关闭该 epoch 所有任务并使对应 SSH 会话失败；重连只承载新会话。

## 7. WebSocket 字节流细节

smux 独占数据 NetConn 的读写；禁止同时在该 WSS 用 wsjson 或另一个 reader 读控制消息。NetConn 将多条 binary WS message 适配为连续字节流；不依赖 message 边界。text 帧应拒绝。[S12][S25]

NetConn 会禁用库的默认 ReadLimit，且其 deadline 命中时可能关闭连接。不要以“调用过 SetReadLimit”代替整体内存/吞吐防护。smux、业务报头、待处理流、TLS/HTTP 和应用输出均需独立边界。[S25]

## 8. 浏览器终端与 HTTP

终端 subprotocol `web-ssh-terminal.v1`：binary 双向传原始终端字节；Server text `terminal.state/terminal.exit`；浏览器 text `terminal.resize/terminal.close`。只有 active 后接受输入；rows/cols 范围建议 1..1000。单会话一个浏览器消费者，重新 attach/多人共享暂未确定。

`GET /api/v1/hosts`：先授权后筛选；重复 `label=key=value` 为 AND 草案。
`POST /api/v1/ssh-sessions`：只接受 host_id、login_user、初始终端尺寸；不接受 principal、TTL、CA token、任意目的地址。
`GET /api/v1/ssh-sessions/{id}`：归属/管理员权限校验。
`POST /api/v1/ssh-sessions/{id}/close`：幂等；管理员关他人会话须独立授权。

Idempotency-Key 绑定 user/scope + body hash；同 key 不同 body 冲突，旧已结束资源不重新创建 SSH。公共错误含 code/request_id/message，不暴露 token、私钥或内部主机信息。完整 HTTP 定义见 `api/openapi.yaml`；WebSocket 的逐帧协议以本章与 Schema 为准。
