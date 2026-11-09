# 10 决策与待确认事项

状态：“明确需求”来自用户；“建议”是本文基线；“待确认”不是用户已同意的决定。

| ID | 决策 | 状态 | 取舍 |
|---|---|---|---|
| ADR-01 | Agent 主动 WebSocket 注册并转发本机 sshd | 明确需求 | 不要求主机暴露公网入站 |
| ADR-02 | Go 实现 Server/Gateway 和 Agent | **用户最新明确** | 前端语言未指定 |
| ADR-03 | WebSocket 上使用 smux 转发 SSH | **用户最新明确** | 一 SSH transport 一 stream；共享连接故障域 |
| ADR-04 | 控制 WSS + 常驻 smux 数据 WSS | 建议 | 独立控制与数据；每 Agent 多一条连接 |
| ADR-05 | Server 是 SSH 客户端/明文终点 | 建议，需确认 | 授权和审计方便；Server 可代用户操作 |
| ADR-06 | 每连接临时 key，约 60 秒用户 cert | 短 TTL 为明确需求，其余建议 | 短认证窗口不等于一次性或会话时长 |
| ADR-07 | principal 绑定 host + Linux account；后台用户授权在 Server | 建议，满足用户动态授权关注 | 主机无须同步后台用户名单 |
| ADR-08 | 专用 JWK Provisioner | 建议 | OIDC 与签发解耦；Server 持高权限凭据 |
| ADR-09 | Agent mTLS + SSH Host Key pinning | 建议 | 初始注册与轮换需设计 |
| ADR-10 | 不迁移已建立的 SSH transport | 建议 | 重连只创建新会话，不伪恢复 |
| ADR-11 | 静态 principals 文件默认，Command 可选 | 建议 | 文件简单；Command 适合本地动态账号映射 |

ADR-04 **替代旧版“每会话独立数据 WebSocket”建议**。采用 smux 是已确定需求，双 WSS 的布局不是额外用户决定。

## 优先待确认

| ID | 问题 | 影响 |
|---|---|---|
| O01 | 是否接受 Server 可见 SSH 明文并代用户操作？ | 不接受则需要浏览器 SSH 客户端，当前信任模型变化 |
| O02 | 共用 ops 还是每人 Linux 账号？root/sudo 如何管理？ | 本地账号、隔离和审计 |
| O03 | 现有仓库/目录/前端框架是什么？ | **Go 与 smux 已定，不重复询问语言** |
| O04 | 单副本还是多副本？Agent/并发/吞吐目标？ | owner 路由与资源预算 |
| O05 | 60 秒是签发后剩余窗口还是严格总区间？ | backdate 与时钟预算 |
| O06 | 浏览器断开、控制断开时是否立刻结束会话？ | 建议控制失联关闭整个 epoch；浏览器语义另定 |
| O07 | 撤权/禁用/登出是否立即踢全部会话，完成时限多少？ | 事件分发、确认和界面状态 |
| O08 | 单租户/多租户；谁管理授权 label？ | 示例 tenant 不是产品承诺 |

## 其余待定

IdP/MFA；机器注册信任；CA 与 JWK 隔离；Host CA/KRL；API/session/heartbeat/配额值；是否录像、SFTP、exec、上传下载、多用户协作；Agent 是否承担安装/更新主机配置。

不得推导：smux 自带身份认证或加密；短证书自带一次性/踢出；Go 语言代表前端也必须 Go；重连意味着恢复原 SSH transport；本地文件映射包含后台用户名单。
