# 实现协作约束

先读 `HANDOFF.md`、`docs/01-product-spec.md`、`docs/10-decisions-open-questions.md`。

- 区分“用户已明确需求”“建议基线”“待确认决定”。不能用建议内容反向宣称用户已经同意。
- Server/Gateway 与 Agent 使用 Go；sshd 转发使用 `github.com/xtaci/smux`，wire version 显式设为 2。前端技术栈未定。
- 这不是本地 ssh-agent 项目；Agent 的基础职责是经过认证的反向字节流转发。
- 单会话关闭/超时只作用于对应 smux stream；禁止误关共享 Session 或给外层 WebSocket NetConn 设置单会话 deadline。
- 数据 WSS 常驻复用；只在每条 stream 开头交换一次有界 JSON open/ack，之后是纯 SSH 字节。
- 用户访问策略只由可信 Server 判断；浏览器传入 principal、tenant、label、TTL 或 CA 选项不能成为授权依据。
- 一个逻辑连接尝试一个临时密钥；证书绑定精确目标主机与 Linux 账号；Key ID 不充当默认授权机制。
- Host Key/Host Certificate 验证不可省略。Server 上的签发凭据与主机 Agent 凭据必须分离。
- 控制消息、隧道绑定 ticket、SSH 证书、OIDC token、Web session 都是不同对象，不能混用生命周期或一次性语义。
- 不把证书过期当作会话断开；撤权关闭数据通道和 SSH 连接，不能只隐藏 UI。
- 不把数据库故障恢复当作 socket 迁移；断线恢复语义依未决问题确认。
- 增量实现并补负向测试：跨 host/账号/租户、旧 epoch、ticket 重放、签发超时、权限变更竞争、主机密钥变化。
- 本包不授权修改生产 sshd。配置变更前保留带外访问，检查 `sshd -t` 与最终生效配置，避免全局关闭现有应急认证。
- 文档和 issue 默认使用中文；代码标识符可用英文。不要在日志、测试快照或提交中包含任何真实密钥或 token。
