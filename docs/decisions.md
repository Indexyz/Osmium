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
| — | 审计 | 参考 Teleport 的审计日志：事件追加写入本地分段文件；配置 `audit.s3` 后，封口的分段 gzip 上传到 S3 兼容存储（AWS S3、MinIO、RustFS），本地只作缓冲。管理员通过 `GET /api/v1/admin/audit` 按时间、用户等字段查询。不做防篡改 |
| — | 前端依赖 | 使用 React + `ghostty-web`（WASM），由 Vite 本地打包并嵌入 Server 二进制（`web/dist`），不再依赖外部 CDN，支持离线部署 |

## 尚未实现

- 会话状态的持久化，多副本部署。审计已可通过 S3 共享，并按 `server_id` 区分。
- 审计日志的防篡改，例如哈希链、签名或 Object Lock。当前不需要，所以没有做。
- 审计全文检索或 Athena 一类的分析查询。目前只支持按时间和字段做精确过滤。
- SSH host CA 校验。
- 管理 UI：目前只有 API：`GET /api/v1/admin/agents` 和 `GET /api/v1/admin/audit`。
- 会话录制，以及 SFTP、端口转发。
- CLI 令牌列表和集中吊销：目前只能在 CLI 上执行 `osmium logout`，或者重启 Server。
