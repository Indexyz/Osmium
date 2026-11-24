---
"osmium": minor
---

新增无 Agent 直连 Zero Trust SSH 证书签发与内置本地只读 `osmium ssh-agent`：

- **策略、SQLite 持久化与独立 `direct_ca` 签发**：主机新增 `connection_mode`（`tunnel` / `direct` / `both`）与 `ssh_address`；新增 `cert_roles` 角色/组级多主机 principal 与 TTL/扩展策略（含 SQLite `state_db` 自动迁移与管理员增量 API `GET/PUT/DELETE /api/v1/admin/cert-roles/{role_id}`）；Server 新增独立 `direct_ca` 配置段与 `POST /api/v1/direct-certs`（仅限 CLI Bearer、临时公钥一次性防重放、签发后二次复核，并支持 `none` / `static` / `client_ip` + `trusted_proxies` 可选 `source-address` 限制）及 `GET /api/v1/host-cas`。
- **CLI 直连工作流与原生 OpenSSH 集成**：`osmium ssh` 自动识别直连/离线回退主机（支持 `--direct` 与跨平台直连，不再依赖隧道 `ProxyCommand`）；新增 `osmium cert login|sign|ensure` 与 `osmium ssh-config`（生成 `Match exec` 或 `--use-agent` + `@cert-authority` `known_hosts`，原生支持 `ssh`/`scp`/`rsync`/VS Code Remote-SSH/Ansible）。
- **内置常驻只读 `osmium ssh-agent`**：本地 OpenSSH Agent 守护进程，临时私钥与证书仅存内存不落盘、拒绝外部 `ssh-add`/删除/锁定、到期前自动轮换全新 Ed25519 密钥续签，探测到吊销或禁用（`401`/`403`）及进程退出时立即清零内存私钥。
- **Web UI 与模板文档**：主机列表支持 `direct` 状态筛选与展示（仅 CLI 直连主机禁用浏览器终端连接以避免 SSRF）；补充直连 `step-ca` / `sshd` 配置模板与 [docs/direct-ssh.md](docs/direct-ssh.md)。
