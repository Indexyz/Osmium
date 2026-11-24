# 无 Agent 直连模式（Zero Trust SSH 证书与内置 `osmium ssh-agent`）

除面向 NAT / 内网受限主机的 `osmium-agent` 反向隧道外，Osmium 还支持作为完整的 Zero Trust SSH 证书签发平台，直接向**未安装 Agent 的普通 `sshd` 服务器**签发短期 OpenSSH 用户证书，并提供本地内置只读 `osmium ssh-agent` 守护进程。

## 架构概览

```
                        ┌─▶ POST /api/v1/direct-certs (Bearer only) ─▶ Server ─▶ step-ca (direct_ca)
                        │                                                 │
osmium ssh / cert /     │                                         授权校验 + TTL 封顶
osmium ssh-agent        │                                         + source-address(可选)
                        │                                         + 临时公钥一次性防重放
                        │                                                 ▼
本机 OpenSSH (ssh/scp/  └─────────────── 直接 TCP SSH（无需隧道/无 Agent）───────────────▶ 目标 sshd
rsync/VS Code/Ansible)         （TrustedUserCAKeys + AuthorizedPrincipalsFile + Host CA 校验）
```

> 安全边界：浏览器 Web 终端**始终只允许连接隧道模式主机**（不提供服务端直连 TCP 代理），避免服务端 SSRF 攻击面。所有直连证书接口均强制 CLI Bearer Token 认证，禁止浏览器 Cookie 调用。

## 三种客户端工作流

### 1. `osmium ssh`（自动识别隧道与直连，单主机短期证书）

- 策略中 `connection_mode` 为 `"direct"` 的主机，或 `"both"` 且 Agent 离线的主机，`osmium ssh [login@]host-id` 会自动切换到直连模式（也可用 `--direct` 强制直连）。
- 每次连接在本地生成全新一次性 Ed25519 密钥，向 `POST /api/v1/direct-certs`（`mode: "host"`）申请单主机精确 principal（`tenant:<scope>:host:<id>:login:<user>`，默认 60 秒）证书。
- 严格校验服务端下发的固定 `ssh_host_keys` 或全局 `host_ca_public_keys`（`StrictHostKeyChecking=yes`），不经 `ProxyCommand` 隧道直连 `ssh_address`（跨平台支持 Linux / macOS / Windows）。

```sh
osmium hosts
osmium ssh ops@edge-db-1
osmium ssh --direct ops@dual-host-1
```

### 2. 本地内置 `osmium ssh-agent`（内存持有 + 自动密钥轮换 + 吊销秒清）

对于希望在日常工作流中直接使用原生 `ssh`、`scp`、`rsync`、VS Code Remote-SSH 或 Ansible 连接大量无 Agent 主机的用户，可以运行内置只读 SSH Agent：

```sh
# 启动常驻只读 ssh-agent（前台运行，可用 systemd --user / launchd 托管）
osmium ssh-agent --ttl 4h

# 在当前 shell 中接入（或用 osmium ssh-config --use-agent 写入 IdentityAgent）
export SSH_AUTH_SOCK="$(osmium ssh-agent ... 输出的路径)"
ssh ops@10.0.2.15
```

安全特性：
- **私钥仅存内存，永不落盘**：每次签发/续签都生成全新临时 Ed25519 密钥，旧私钥切片在轮换、吊销或进程退出时立即清零（`clear()`）。
- **只读托管（Read-only）**：仅响应 OpenSSH Agent 的 `List` / `Sign` / `SignWithFlags`，拒绝外部 `ssh-add` 注入、删除或锁定密钥；且只暴露已签名的证书身份，不暴露未签名裸公钥。
- **自动密钥轮换续签**：在到期前（默认剩余 1/4 有效期，最长 15 分钟）自动生成新密钥向 Server 续签并原子切换。
- **吊销/禁用快速清零**：后台按 `--check-interval`（默认 60 秒）探测 `GET /api/v1/me`，一旦收到 `401`（CLI Token 被吊销）或 `403`（用户被策略禁用），立即清空内存密钥；若续签时被拒或证书自然过期，同样立即清零。

### 3. `osmium cert` 与 `osmium ssh-config`（原生 OpenSSH 无缝集成）

支持两种原生 `~/.ssh/config` 集成方式：

- **角色/Agent 方式（适合大批量/动态弹性主机）**：配合 `osmium ssh-agent` 与 SSH Host CA，即便主机未在 `policy.json` 逐台登记，也可凭角色 principal 直接登录：
  ```sh
  osmium ssh-config --use-agent --match-pattern "*.prod.internal" --write ~/.ssh/config.d/osmium.conf
  ```
- **按主机自动按需签发方式（`Match exec`）**：无需常驻 `osmium ssh-agent`，执行 `ssh edge-db-1` 或 `scp` 时 OpenSSH 自动调用 `osmium cert ensure` 按需签发/复用未过期的单主机短期证书：
  ```sh
  osmium ssh-config --write ~/.ssh/config.d/osmium.conf
  # 在 ~/.ssh/config 顶部添加：Include config.d/osmium.conf
  ssh edge-db-1
  ```
- **手动签发证书（如 CI/Ansible 或加载到系统 `ssh-agent`）**：
  ```sh
  osmium cert login --ttl 4h                  # 签发角色级证书（默认加载到 SSH_AUTH_SOCK）
  osmium cert login --ttl 2h -p role:prod-ops # 仅申请授权集合中的子集 principal
  osmium cert sign ops@edge-db-1              # 为单台主机签发短期证书
  ```

## 服务端配置（`direct_ca` 与 `cert_roles`）

### 1. 独立的 `step-ca` Provisioner

为避免与隧道模式的 60 秒 loopback 证书（`web-user-loopback.tpl`）混淆安全域，直连证书要求在 `server.json` 中显式配置 `direct_ca`（未配置时默认 fail-closed 禁用 `POST /api/v1/direct-certs`）。

推荐使用独立 JWK Provisioner（例如 `direct-ssh`）：
- Provisioner 时长配置参考 [direct-provisioner.fragment.json](design/config/step-ca/direct-provisioner.fragment.json)（如 `30s`–`8h`）。
- SSH 模板参考 [direct-user.tpl](design/config/step-ca/direct-user.tpl)：支持多 principal、按需写入 `.Token.osmium_extensions` 与可选 `.Token.osmium_source_address`。
- X.509 模板同样使用 [deny-x509.tpl](design/config/step-ca/deny-x509.tpl)。

### 2. `server.json` 中的 `direct_ca`

```json
"direct_ca": {
  "provisioner_name": "direct-ssh",
  "jwk_file": "/etc/osmium/direct-provisioner.jwk",
  "jwk_password_file": "/etc/osmium/direct-provisioner.password",
  "default_host_ttl": "60s",
  "default_role_ttl": "4h",
  "max_role_ttl": "8h",
  "allowed_extensions": ["permit-pty", "permit-user-rc", "permit-port-forwarding"],
  "source_address_mode": "none",
  "source_address_cidrs": "",
  "trusted_proxies": []
}
```

`url`、`root_ca_file`、`user_ca_public_key_file` 若省略，将自动继承顶层 `ca` 配置。

**可选 `source_address_mode` 策略**：
- `"none"`（默认）：不写入 `source-address` critical option（适用于移动办公或经跳板机场景）。
- `"static"`：强制写入 `source_address_cidrs` 指定的企业出口 / VPN 网段（如 `"198.51.100.0/24,10.20.0.0/16"`）。
- `"client_ip"`：动态锁定为申请证书时的客户端源 IP（IPv4 `/32` 或 IPv6 `/128`）。**仅当 TCP 对端位于 `trusted_proxies` 内时，才从右向左解析 `X-Forwarded-For`**，防止客户端伪造请求头绕过。

### 3. 策略中的直连主机与角色（`cert_roles`）

参考 [policy.example.json](../examples/policy.example.json)：
- 主机可设置 `"connection_mode": "direct"`（无需 `agent` 字段，必填 `ssh_address` 如 `"10.0.2.15:22"`）或 `"both"`（同时配置 `agent` 与 `ssh_address`；Agent 在线走隧道，离线自动回退直连或 `--direct` 手动直连）。
- 顶层 `cert_roles` 定义角色/组级直连 principal、最大有效期（`1m`–`24h`，再受 `direct_ca.max_role_ttl` 二次封顶）与允许的扩展子集；支持通过管理员增量 API `GET/PUT/DELETE /api/v1/admin/cert-roles/{role_id}` 热更新并持久化至 `state_db`。

### 4. 目标 `sshd` 配置

参考 [91-osmium-direct-ca.conf.example](design/config/sshd/91-osmium-direct-ca.conf.example)，部署 `TrustedUserCAKeys` 与 `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u`：
- 若仅允许单主机精确证书：在 `/etc/ssh/auth_principals/ops` 中写入 `tenant:<scope>:host:<id>:login:ops`。
- 若同时允许角色/组证书（`osmium ssh-agent`）：在对应环境机器的 `/etc/ssh/auth_principals/ops` 中追加角色 principal（如 `role:prod-ops`）。
- 建议为目标 `sshd` 签发由 Osmium `host_ca_public_keys` 信任的 SSH Host Certificate，实现全网无 TOFU 自动校验主机身份。
