# 默认决定与未实现功能

[design/10-decisions-open-questions.md](design/10-decisions-open-questions.md) 里有一些问题留给产品决定。在得到确认之前，暂时按下表实现：

| 编号 | 问题 | 当前实现 |
| --- | --- | --- |
| O01 | Server 能否看到明文 | Web 模式下能：Server 就是 SSH 客户端。原生模式下不能：Server 只转发字节 |
| O04 | 多副本 | 单副本，配置固定的 `server_id`。状态全部在内存中，重启后会话丢失 |
| O05 | 60 秒的含义 | 按“签发后剩余约 60 秒”处理。step-ca 默认把 `valid_after` 往前回拨 1 分钟（`authority.backdate`），所以证书的总区间是 120 秒。已在真实 step-ca 0.30.2 上测得。想要严格的总区间，可以在 step-ca 的 `ca.json` 中调小 `authority.backdate`，例如设为 `"5s"` 时总区间约 65 秒。这个设置对整个 CA 生效 |
| O06 | 浏览器断开 | 立即关闭该会话，不支持重新 attach。control 或 data 任一通道断开，都会结束整个 epoch 及其会话 |
| O07 | 撤销后活跃会话如何处理 | 立即关闭，可通过 `sessions.revoke_active` 关闭这一行为 |
| — | 会话时长 | 证书过期不影响已建立的会话。最长时长由 `max_session_duration` 控制，默认 8 小时 |
| — | Agent 身份 | 用专用客户端 CA 做 mTLS，CN 映射到策略中的主机 |
| — | 主机身份 | 只支持登记固定的 host key，尚未支持 host CA |
| — | 桌面 ssh-agent / 原生 OpenSSH | 已通过 `osmium ssh` 实现，见 [native-ssh.md](native-ssh.md)。CLI 令牌与 Web 会话的有效期相同 |
| — | 审计 | 参考 Teleport 的文件审计日志，追加写入 `audit.dir`，每个 UTC 日一个 JSONL 文件，按 `audit.retention` 清理。管理员通过 `GET /api/v1/admin/audit` 查询。单副本、本地磁盘，不防篡改 |
| — | 前端依赖 | xterm.js 从 jsDelivr 加载（CSP 已放行）。离线部署需要改为本地托管 |

## 尚未实现

- 会话状态的持久化，多副本部署（多副本需要共享的审计存储）。
- 审计日志的防篡改（哈希链或签名）和外部存储后端。
- SSH host CA 校验。
- 管理 UI：目前只有 API：`GET /api/v1/admin/agents` 和 `GET /api/v1/admin/audit`。
- 会话录制，以及 SFTP、端口转发。
- CLI 令牌列表和集中吊销：目前只能在 CLI 上执行 `osmium logout`，或者重启 Server。
