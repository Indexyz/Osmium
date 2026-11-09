# 默认决定与未实现功能

[design/10-decisions-open-questions.md](design/10-decisions-open-questions.md) 里有一些问题留给产品决定。在得到确认之前，暂时按下表实现：

| 编号 | 问题 | 当前实现 |
| --- | --- | --- |
| O01 | Server 能否看到明文 | Web 模式下能：Server 就是 SSH 客户端。原生模式下不能：Server 只转发字节 |
| O04 | 多副本 | 单副本，配置固定的 `server_id`。状态全部在内存中，重启后会话丢失 |
| O06 | 浏览器断开 | 立即关闭该会话，不支持重新 attach。control 或 data 任一通道断开，都会结束整个 epoch 及其会话 |
| O07 | 撤销后活跃会话如何处理 | 立即关闭，可通过 `sessions.revoke_active` 关闭这一行为 |
| — | 会话时长 | 证书过期不影响已建立的会话。最长时长由 `max_session_duration` 控制，默认 8 小时 |
| — | Agent 身份 | 用专用客户端 CA 做 mTLS，CN 映射到策略中的主机 |
| — | 主机身份 | 只支持登记固定的 host key，尚未支持 host CA |
| — | 桌面 ssh-agent / 原生 OpenSSH | 已通过 `osmium ssh` 实现，见 [native-ssh.md](native-ssh.md)。CLI 令牌与 Web 会话的有效期相同 |
| — | 审计 | 以 JSON 写到 stdout，管理接口保留最近 1000 条，没有数据库 |
| — | 前端依赖 | xterm.js 从 jsDelivr 加载（CSP 已放行）。离线部署需要改为本地托管 |

## 尚未实现

- 审计和会话的持久化存储，多副本部署。
- SSH host CA 校验。
- 管理 UI：目前只有 `GET /api/v1/admin/agents`。
- 会话录制，以及 SFTP、端口转发。
- CLI 令牌列表和集中吊销：目前只能在 CLI 上执行 `osmium logout`，或者重启 Server。
