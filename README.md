# Osmium

基于 Web 的 SSH 访问系统。用户在浏览器里通过 OIDC 登录，按标签筛选有权访问的主机并打开终端。每次连接时，Server 向 step-ca 申请一张有效期约 60 秒的 SSH 用户证书，再经由主机上的 Agent 反向隧道连到本机 sshd。

设计文档在 `docs/design/`（来自 handoff v0.2），实现约束见 `AGENTS.md`。

## 架构

```
浏览器 ──HTTPS/WSS──▶ Server（Web API + SSH Gateway + Agent 管理）──HTTPS──▶ step-ca
                          ▲
                          │ WSS × 2（mTLS）：control（JSON）+ data（smux v2）
                          │
                       Agent ──TCP──▶ 127.0.0.1:22（sshd）
```

- **Agent** 主动连出到 Server，维持两条长连接：
  - `/agent/v1/control`：注册、心跳和关闭会话；
  - `/agent/v1/data`：二进制 WebSocket，上面跑 smux。
- 每个 SSH 尝试独占一个 smux stream。stream 开头是长度前缀的 JSON prelude（`ssh.open` / `ssh.open_result`），确认之后只传原始 SSH 字节。关闭某个会话只关它自己的 stream，不关闭共享的 Session。
- **Server** 本身就是 SSH 客户端。每次尝试都会：
  1. 生成一次性的 ed25519 密钥；
  2. 向 step-ca 签发证书，principal 为 `tenant:<scope>:host:<id>:login:<user>`；
  3. 校验返回的证书；
  4. 用策略里固定的主机公钥做 host key 校验，然后建立 PTY shell。
- 授权完全在服务端，由策略文件定义。浏览器只能提交 `host_id`、`login_user` 和终端尺寸，principal、TTL、标签和 CA 参数都由服务端决定。Agent 上报的标签只用于展示，不参与授权。

## 目录

| 路径 | 内容 |
| --- | --- |
| `cmd/osmium` | 唯一的可执行文件（cobra）：`server`、`agent`、`dev pki`、`version`、`completion` |
| `internal/tunnel` | smux 传输层、prelude 编解码、Agent 端 stream 处理 |
| `internal/protocol` | control 消息和终端消息 |
| `internal/agenthub` | Agent 注册、epoch、data ticket 和 stream 分配 |
| `internal/ca` | step-ca JWK provisioner 客户端和证书校验；`catest` 为测试用的假 CA |
| `internal/sshgateway` | SSH 客户端（临时密钥、host key 固定） |
| `internal/sessions` | 会话状态机和多次授权复核 |
| `internal/authz` | 策略、授权和主机可见性 |
| `internal/authn` | OIDC 登录（PKCE / state / nonce）和 Web 会话 |
| `internal/server` | HTTP API 和终端 WebSocket |
| `internal/e2e` | 端到端测试（真实 sshd） |
| `web/` | 前端（原生 JS + xterm.js） |
| `examples/` | 配置示例 |

## 构建与测试

```sh
go build -o osmium ./cmd/osmium
# 注入版本号：go build -ldflags "-X main.version=v0.1.0" -o osmium ./cmd/osmium
./osmium --help
go test -race ./...          # e2e 需要 PATH 中有 sshd；加 -short 可跳过
E2E_LOG=1 go test -run TestShellOverSharedTunnel -v ./internal/e2e/   # 带审计日志
```

端到端测试会以当前用户身份，在回环地址的随机端口上启动无特权 sshd，并用进程内的假 step-ca 签发证书。不会改动系统里的 sshd。覆盖的场景：
- 共享隧道上的多会话隔离、关闭单个会话、正常退出码；
- 动态授权与撤销；
- 伪造标签无效；
- principal 绑定主机和登录名；
- host key 不匹配、CA 不可用；
- Origin、CSRF、幂等、多余字段、越权访问；
- Agent 重启后 epoch 递增、data ticket 一次性；
- 激活前撤销。

## 部署

### 1. step-ca

按 `docs/design/04-ca-integration.md` 新建一个专用的 JWK provisioner（例如名为 `web-ssh`）：
- 证书时长取 `docs/design/config/step-ca/provisioner.fragment.json`；
- SSH 模板用 `web-user.tpl`；
- X.509 模板用 `deny-x509.tpl`，即禁止签发 X.509。

Server 需要以下文件：
- 该 provisioner 的加密 JWK 及其密码文件；
- step-ca 根证书；
- SSH User CA 公钥（`step ssh config --roots`），用来校验 step-ca 返回的证书。

### 2. 目标主机

在 sshd 中加入 `docs/design/config/sshd/90-web-ssh-ca.conf.example` 里的配置：
- `TrustedUserCAKeys`；
- `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u`。

然后为每个允许的登录名写 principal 文件。例如主机 `host-123` 允许 `ops` 登录：

```
# /etc/ssh/auth_principals/ops
tenant:t1:host:host-123:login:ops
```

改动生产环境的 sshd 前，务必先评审合并后的配置，并保留应急访问方式。

### 3. Agent mTLS

生产环境请用自己的 PKI，为每个 Agent 签发客户端证书，CN 与策略中的 `agent.client_cert_cn` 一致。本地试用可以用：

```sh
osmium dev pki -o dev/pki --server-hosts localhost,127.0.0.1 --agents agent-123
```

### 4. 策略与启动

参考 `examples/policy.example.json`，每台主机需要填写：
- `ssh_host_keys`：必填，来自 `/etc/ssh/ssh_host_*_key.pub`；
- `allowed_login_users`；
- `policy_labels`；
- 绑定的 Agent。

`grants` 描述谁可以以哪些登录名访问哪些主机。修改策略文件后向 Server 发送 `SIGHUP` 即可热加载：授权被撤销的活跃会话会立即关闭，不需要改动主机。

```sh
osmium server -c examples/server.example.json
osmium agent  -c examples/agent.example.json
```

本地开发可以在 server 配置里设置 `"dev_login": true`，代替 OIDC，然后访问 `/auth/dev-login?user=alice&group=ops`。**生产环境禁止开启。**

## 当前的默认决定

handoff 里留给产品决定的问题，暂时按以下方式实现，需要确认：

| 编号 | 问题 | 当前实现 |
| --- | --- | --- |
| O01 | 服务端能否看到明文 | 能。Server 就是 SSH 客户端，终止 SSH 连接 |
| O04 | 多副本 | 单副本，配置固定的 `server_id`；状态全部在内存中，重启后会话丢失 |
| O06 | 浏览器断开 | 立即关闭该会话，不支持重新 attach；control/data 任一通道断开都会结束整个 epoch 及其会话 |
| O07 | 撤销后活跃会话如何处理 | 立即关闭（`sessions.revoke_active`，可关掉） |
| — | 会话时长 | 证书过期不影响已建立的会话；最长时长由 `max_session_duration` 控制，默认 8 小时 |
| — | Agent 身份 | 用专用客户端 CA 做 mTLS，CN 映射到策略中的主机 |
| — | 主机身份 | 只支持固定 host key，尚未支持 host CA |
| — | 审计 | 以 JSON 写到 stdout，管理接口保留最近 1000 条；没有数据库 |
| — | 前端依赖 | xterm.js 从 jsDelivr 加载（CSP 已放行），离线部署需要改为本地托管 |

## 尚未实现

- 审计和会话的持久化存储；多副本部署。
- SSH host CA 校验。
- 管理 UI：目前只有 `GET /api/v1/admin/agents`。
- 会话录制。
