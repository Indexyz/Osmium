# 部署

配置示例在 [`examples/`](../examples/)。

## 1. step-ca

按 [design/04-ca-integration.md](design/04-ca-integration.md) 新建一个专用的 JWK provisioner，例如命名为 `web-ssh`：
- 证书时长取 [provisioner.fragment.json](design/config/step-ca/provisioner.fragment.json)；
- SSH 模板用 [web-user.tpl](design/config/step-ca/web-user.tpl)，只允许一个 principal，只带 `permit-pty`；
- X.509 模板用 [deny-x509.tpl](design/config/step-ca/deny-x509.tpl)，禁止签发 X.509。

Server 需要以下文件（对应 `ca.*` 配置项）：
- 该 provisioner 的加密 JWK 及其密码文件；
- step-ca 根证书；
- SSH User CA 公钥（`step ssh config --roots`），用来校验 step-ca 返回的证书。

## 2. 目标主机

在 sshd 中加入 [90-web-ssh-ca.conf.example](design/config/sshd/90-web-ssh-ca.conf.example) 里的配置，即 `TrustedUserCAKeys` 和 `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u`。然后为每个允许的登录名写 principal 文件，例如：

```
# /etc/ssh/auth_principals/ops
tenant:t1:host:host-123:login:ops
```

改动生产环境的 sshd 前，务必先评审合并后的配置，并保留应急访问方式。详见 [design/config/README.md](design/config/README.md)。

## 3. Agent mTLS

为每个 Agent 签发客户端证书，CN 必须与策略中的 `agent.client_cert_cn` 一致。生产环境请用自己的 PKI。本地试用可以用：

```sh
osmium dev pki -o dev/pki --server-hosts localhost,127.0.0.1 --agents agent-123
```

## 4. 策略

参考 [policy.example.json](../examples/policy.example.json)：
- `hosts`：每台主机需要填写
  - `ssh_host_keys`：必填，来自 `/etc/ssh/ssh_host_*_key.pub`；
  - `allowed_login_users`；
  - `policy_labels`；
  - 绑定的 Agent。
- `grants`：描述谁可以以哪些登录名访问哪些主机。主体可以是用户 ID、`issuer + subject` 或组；主机可以按 ID 或标签选择。
- `admins`：管理员可以关闭他人的会话，但不能观看。

修改策略文件后向 Server 发送 `SIGHUP` 即可热加载：
- 授权被撤销的活跃会话会立即关闭，可通过 `sessions.revoke_active` 关闭这一行为；
- 不需要改动主机。

## 5. 启动

```sh
osmium server -c /etc/osmium/server.json   # 参考 examples/server.example.json
osmium agent  -c /etc/osmium-agent/agent.json   # 参考 examples/agent.example.json
```

- Server 的 Web 监听（`listen`）建议放在 HTTPS 反向代理之后，或直接配置 `tls_cert` / `tls_key`。
- `public_url` 必须是浏览器实际访问的地址，用于 Origin 校验。
- Agent 监听（`agent_listen`）强制 mTLS。
- 审计日志以 JSON 输出到 stdout。
