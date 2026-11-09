# 原生 SSH 客户端与 ssh-agent

除了浏览器终端，用户也可以用本机的 OpenSSH 客户端连接，使用自己的终端、键位和 ssh 选项。私钥只在用户本机生成，并以限时方式加载到用户的 ssh-agent。

## 使用

```sh
osmium login --server https://ssh.example.com   # 浏览器中确认授权，只需一次
osmium hosts                                     # 列出有权访问的主机
osmium hosts -l env=prod                         # 按策略标签筛选
osmium ssh host-123                              # 只允许一个登录名时可省略
osmium ssh ops@host-123                          # 指定登录名
osmium ssh ops@host-123 uptime                   # 远程命令，退出码原样返回
osmium ssh --no-agent ops@host-123               # 不使用 ssh-agent
osmium logout                                    # 在 Server 端吊销并删除本地令牌
```

- `host-id` 之后的参数原样传给 `ssh`。
- 令牌保存在 `~/.config/osmium/credentials.json`，权限 0600。可以用 `OSMIUM_CONFIG` 环境变量改目录。
- Server 使用私有 CA 时，加 `--ca-file`。

## 流程

1. **登录**：`osmium login` 在 `127.0.0.1` 上监听一个随机端口，并在浏览器打开 `/auth/cli`。
   1. 用户在已登录的 Web 会话里点击“授权”。这一步是带 CSRF 和同源校验的 POST。
   2. Server 只会重定向回 `http://127.0.0.1:<port>/callback`，附带一次性的 code，有效期 2 分钟。
   3. CLI 用 PKCE verifier 换取 Bearer 令牌。
   
   令牌与 Web 会话相互独立，有效期等于 `web_session_ttl`，Server 端只保存它的哈希。
2. **连接**：`osmium ssh` 依次执行以下步骤。
   1. 生成一次性的 ed25519 密钥，调用 `POST /api/v1/native-sessions`，只提交 `host_id`、`login_user` 和公钥。Server 做授权检查，同一把公钥不能重复使用。
   2. 打开 `GET /api/v1/ssh-sessions/{id}/tunnel`。这是 WebSocket，子协议为 `osmium-native-ssh.v1`，只接受 Bearer 认证。
   3. Server 让 Agent 打开 stream，Agent 确认后再向 step-ca 签发证书，然后再复核一次授权，最后发送 `native.ready`，内容是证书和策略里登记的主机公钥。
   4. CLI 把私钥和证书加入 `SSH_AUTH_SOCK` 指向的 ssh-agent，有效期约 90 秒，到期由 agent 自动删除，ssh 退出时 CLI 也会主动删除。
   5. CLI 用临时 known_hosts 启动本机 `ssh`，参数包括 `StrictHostKeyChecking=yes`、`HostKeyAlias`、`IdentitiesOnly=yes` 和 `ProxyCommand`。`ProxyCommand` 经由 `osmium proxy-connect` 把字节转发到隧道上。
3. **结束**：ssh 退出、管理员关闭会话、授权被撤销、达到最长时长或 Agent 断开，任何一种情况都只关闭本会话自己的 stream。

## 安全性质

- 私钥不离开用户本机，每次连接都换一把新密钥。证书只有一个 principal，有效期约 60 秒；证书过期不影响已经建立的连接。
- 主机公钥必须与策略登记的一致，不读用户的 `known_hosts`，也不会写入。
- 隧道只接受 Bearer 令牌，浏览器无法凭 Cookie 打开它。原生会话也不能以 Web 终端的方式附加。
- 原生模式下 Server 看不到会话明文，审计只记录元数据：用户、主机、登录名、证书序列号、密钥指纹和时间。
- 证书只带 `permit-pty`，因此端口转发、agent 转发和 X11 转发都会被 sshd 拒绝。
- 不使用 ssh-agent 时（`--no-agent`，或者没有 `SSH_AUTH_SOCK`），私钥写入权限为 0700 的临时目录，ssh 退出后删除。
