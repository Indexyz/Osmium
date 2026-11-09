# 12 Go 实现指南

## 1. 包边界

```text
cmd/server                HTTP API、OIDC、Agent 管理、SSH Gateway 的入口
cmd/agent                 常驻机器 Agent 入口
internal/authn            OIDC、Web session、机器身份
internal/authz            host/login 授权、label policy、撤权事件
internal/inventory        主机注册与可信 Host Key
internal/agenthub         控制 WSS、owner/epoch、数据 ticket、presence
internal/tunnel           WSS NetConn、smux、open/ack、stream registry、relay
internal/ca               JWK OTT、step-ca HTTPS 签发、响应检查
internal/sshgateway       临时 key、cert signer、HostKeyCallback、PTY
internal/sessions         状态机、取消、幂等、超时、reconcile
internal/audit            元数据事件，禁止 token/私钥和隐式终端录像
web                       浏览器终端 UI；框架待定
```

以上为建议目录，不是已存在仓库。本包 `reference/go` 只覆盖部分传输核心。

## 2. 依赖选型与锁定

| 功能 | 选型 | 本包状态 |
|---|---|---|
| 多路复用 | `github.com/xtaci/smux` | 参考模块固定 v1.5.57；wire Version=2 |
| WebSocket | `github.com/coder/websocket` | 参考模块固定 v1.8.15，默认关闭压缩 |
| SSH 客户端 | `golang.org/x/crypto/ssh` | API 路线已选，实际 release 与完整应用一起锁定 |
| OIDC | 符合 OIDC Core 的 Go 库 | IdP 和具体库待选，不自行手写安全校验 |
| HTTP/TLS/取消 | Go `net/http`、`crypto/tls`、`context` | 发布用当时受支持且已修补的 Go 版本 |

v1.5.57 和 v1.8.15 是可核对标签，不声称最新。其 API/源码来源见 [S22]–[S25]。参考模块 go.mod 使用 Go 1.23 作为依赖最低版本起点，不表示推荐用旧工具链上线。

## 3. 正确的 smux 嵌套

```go
// 结构示意，不包含 HTTP/mTLS/ticket 校验：必须先由上层完成。
raw := websocket.NetConn(tunnelContext, ws, websocket.MessageBinary)
cfg := smux.DefaultConfig()
cfg.Version = 2

// Gateway（即使它是 WebSocket Accept 方）：
mux, err := smux.Client(raw, cfg)
// Agent（即使它是 WebSocket Dial 方）：
// mux, err := smux.Server(raw, cfg)
```

必须检查 err、拒绝不匹配 subprotocol、在任何失败路径关闭适当的资源。两端 smux config 由可信部署配置确定，不相信 Agent 自报的无限资源参数。

Gateway 完成业务授权之后 OpenStream，完成 open/ack 才将它交给 `ssh.NewClientConn(stream, expectedHostIdentity, sshConfig)`。`sshConfig.User` 是目标 Linux 账号，Auth 只用本次用户证书对应 signer；HostKeyCallback 校验可信 pin/Host CA。[S11]

不要给 `NewClientConn` 传整个数据 NetConn，否则一个 SSH 会话会侵占 smux 协议。不要按 `stream.RemoteAddr()`（可能是代理地址）判断目标 Host Key 身份，应绑定所选 host 的可信身份。

## 4. cancellation 与注册表

每个 tunnel 一个父 context，每个 stream/SSH transport 一个子 context。Agent 在校验 open 后、TCP dial 前原子注册 attempt；close 找到对应 cancel。若 close 早于注册，用有界 tombstone/取消状态避免稍后 open 被意外激活。

Gateway 阶段期限：stream open/ack、CA 签发、SSH 认证分别管理，不能拿证书期限作为 I/O deadline。新证书还有多久可用是签发/认证判断，不应限制已建立的会话。

每个 relay 两个复制方向、一个取消来源；正常 EOF 对目的写侧 CloseWrite，反方向继续收尾；非 EOF 错误/取消则 full-close。退出后等待两个复制 goroutine，回收计数和注册表项。库 Close 的内部时限不等于产品期望的立即释放；拥塞/底层黑洞须实测。

## 5. 配额和内存

并发配额必须在 goroutine/大缓冲分配前执行。限制 pending stream、active stream、CA 申请、每用户和每主机连接数；不可仅统计 active 而放任大量 waiting_agent/signing。

复制缓冲是固定大小，浏览器输出队列有上限；慢消费者触发背压或明确超时策略。控制 WSS 不共用 smux reader，避免数据流占用同一应用读取循环。shared TCP 的网络级 HOL 无法由 smux 消除。

## 6. 参考代码的适用边界

`wire.go` 提供精确长度 framing 和受限报头，不预读 SSH banner。
`transport.go` 提供已认证 WebSocket 的 smux 包装、Gateway open/ack、Agent 单 stream dial/relay。
`relay.go` 提供 TCP/stream 半关闭与 drain 策略。

上层仍须实现：mTLS/HTTP Upgrade、data ticket、控制注册、配额与全局取消注册表、用户授权、CA/SSH、Web 终端、持久化和审计。参考代码用强制 callback 把 stream 的 attempt 准入留给上层，不包含“默认允许所有请求”的伪授权实现。

不要复制它后便声称生产功能完成。`VALIDATION.md` 明确记录仅标准库部分测试已实际执行，第三方模块整体构建和 smux/WS 集成待在联网环境运行。

## 7. 建议 CI

```sh
cd reference/go
go mod tidy
go mod verify
go test -race ./...
go vet ./...
```

正式仓库应提交真实生成的 go.sum；本包未能联网拉取依赖，不伪造 checksum。再加入真实 sshd/step-ca、负向认证、断线、限流、撤权和资源泄漏测试；CI 成功后记录具体工具链、依赖版本与镜像 digest。
