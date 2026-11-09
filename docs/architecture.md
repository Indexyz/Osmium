# 架构

```
浏览器 ──HTTPS/WSS──┐
                    ├─▶ Server（Web API + SSH Gateway + Agent 管理）──HTTPS──▶ step-ca
osmium CLI + ssh ───┘          ▲
                               │ WSS × 2（mTLS）：control（JSON）+ data（smux v2）
                               │
                            Agent ──TCP──▶ 127.0.0.1:22（sshd）
```

详细设计见 [design/02-architecture.md](design/02-architecture.md) 和 [design/05-protocols.md](design/05-protocols.md)。

## 组件

- **Agent** 运行在目标主机上，主动连出到 Server，维持两条长连接：
  - `/agent/v1/control`：注册、心跳和关闭会话；
  - `/agent/v1/data`：二进制 WebSocket，上面跑 smux v2。

  Agent 只把 stream 转发到本机配置的 sshd，不会连接任意地址。
- **stream**：每次 SSH 连接尝试独占一个 smux stream。
  - stream 开头是带长度前缀的 JSON prelude（`ssh.open` / `ssh.open_result`），确认之后只传原始 SSH 字节。
  - 关闭某个会话只关它自己的 stream，不会关闭共享的 Session。
- **Server** 有两种会话模式：
  - **Web 模式**：Server 本身就是 SSH 客户端。每次尝试都会：
    1. 生成一次性的 ed25519 密钥；
    2. Agent 确认 stream 后，向 step-ca 申请签发证书，principal 为 `tenant:<scope>:host:<id>:login:<user>`；
    3. 校验返回的证书；
    4. 用策略里登记的主机公钥严格校验 host key，然后建立 PTY shell，通过 xterm.js 呈现给浏览器。
  - **原生模式**：用户本机的 OpenSSH 客户端与 sshd 端到端通信，Server 只做授权、签发证书和字节转发，看不到明文。见 [native-ssh.md](native-ssh.md)。
- **授权**完全在服务端，由策略文件定义（[design/03-authorization.md](design/03-authorization.md)）：
  - 客户端只能提交 `host_id`、`login_user`、终端尺寸，原生模式下再加一把公钥；
  - principal、TTL、标签和 CA 参数都由服务端决定；
  - Agent 上报的标签只用于展示。
- **复核**：创建会话、打开 stream、签发证书、激活这四个时刻都会重新检查授权。策略热加载后，被撤销的会话会立即关闭。

## 会话状态

`created → waiting_agent → signing → ssh_authenticating → active → closing → closed`，任一步失败进入 `failed`。

原生模式没有 `ssh_authenticating`，因为 Server 看不到认证过程。见 [design/diagrams/session-state.mmd](design/diagrams/session-state.mmd)。

## 代码目录

| 路径 | 内容 |
| --- | --- |
| `cmd/osmium` | 主程序（cobra）：`server`、`agent`、`login`、`hosts`、`ssh`、`dev pki` 等 |
| `cmd/osmium-agent` | 目标主机上的独立 Agent，依赖最少，面向边缘设备 |
| `internal/tunnel` | smux 传输层、prelude 编解码、Agent 端 stream 处理 |
| `internal/protocol` | control、终端和原生隧道消息 |
| `internal/agenthub` | Agent 注册、epoch、data ticket 和 stream 分配 |
| `internal/ca` | step-ca JWK provisioner 客户端和证书校验；`catest` 为测试用的假 CA |
| `internal/sshgateway` | Web 模式的 SSH 客户端（临时密钥、固定 host key） |
| `internal/sessions` | 会话状态机（Web / 原生）和多次授权复核 |
| `internal/authz` | 策略、授权和主机可见性 |
| `internal/authn` | OIDC 登录、Web 会话、CLI 登录与 Bearer 令牌 |
| `internal/server` | HTTP API、终端 WebSocket 和原生隧道 |
| `internal/client` | CLI 客户端：登录、主机列表、调用本机 ssh |
| `internal/e2e` | 端到端测试（真实 sshd / ssh / ssh-agent） |
| `web/` | 前端（原生 JS + xterm.js） |
| `examples/` | 配置示例 |
