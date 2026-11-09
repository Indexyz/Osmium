# 07 安全与运维

## 必须明确的威胁模型

Server 被完全控制时，可以滥用其 Provisioner 权限、看到会话并代用户执行操作。短 TTL 和 target principal 不能消除此信任。主机 root 被控制时，也不能依靠本机 Agent/sshd 配置保证该主机隔离。商业产品应明确这些边界。

## 安全检查表

| 风险 | 建议控制 |
|---|---|
| 浏览器越权选择 host/login | 每次调用服务端授权；不从表单接受 principal/TTL/地址 |
| 跨主机/账号使用证书 | 精确 target principal；本机独立匹配；负向集成测试 |
| 假 Agent 或克隆凭据 | 独立机器身份、认证注册、epoch、吊销流程、重复连接策略 |
| 伪造 label 获取权限 | policy_labels 与 reported_labels 分离 |
| WSS 被抢接/重放 | mTLS + 绑定共享数据隧道/epoch 的一次性 ticket + 原子消费 |
| Host Key 偷换 | 可信 pin 或受约束 Host CA；变化失败关闭并走轮换流程 |
| CA/JWK 凭据泄漏 | 最小签发权限、网络隔离、受保护存储、密钥轮换与速率限制 |
| token/私钥进入日志 | 统一脱敏；禁用敏感请求/帧体日志；调试和错误栈也检查 |
| 浏览器跨站建立终端 | cookie 保护、CSRF、明确 Origin 校验、session 归属校验 |
| 大帧/慢客户端/资源泄漏 | 有界缓冲、并发配额、超时、背压、失败清理和压测 |
| 改 principals 文件绕过 | root 管理目录与文件，不允许登录用户写入 |
| 多副本旧 owner 越权 | lease/epoch、签发和激活前重查、撤权回执 |

## 初次部署

先建立可信 host/agent 注册与 User CA 公钥分发渠道。保留应急管理员路径、带外控制台与配置备份。增加配置后执行 `sshd -t`；结合目标账号、连接来源检查最终生效配置，如 `sshd -T -C ...`。根据发行版服务名执行 reload，不把配置写好等同于配置已生效。[S01][S18]

包内 sshd 片段只建立证书信任，不会自动禁止已有 password/authorized_keys 认证。是否要求某些管理账号“仅证书登录”需要评估 Match/组/账号策略，不能全局关闭现有应急通道。也要检查其他 CA 信任入口、AuthorizedKeysCommand 和其他配置来源是否绕过 target principal 约束。

Agent 常驻转发通常不需要 root；安装系统配置/凭据是单独的特权初始化步骤。不要为了写 sshd 配置就让所有常驻功能默认 root。

## 证书、限制与 shell 的区别

Web shell 证书模板建议只带 `permit-pty`，不默认允许 agent、port、X11 forwarding 或 user rc；本包提供最小扩展模板草案。[S13]

这些 SSH 功能限制不是 shell sandbox，拥有 shell 的用户依然能按 OS 权限启动网络程序、持久任务或修改可写文件。关闭 SSH 连接不保证目标上所有后台进程被终止；需要强制进程生命周期隔离时应额外设计 cgroup/session 清理，而非依赖证书。

`source-address` 根据 sshd 看到的网络来源判断；在此架构中通常是本机 Agent 的 loopback 地址，不能用它当作浏览器公网 IP 策略。浏览器来源控制放在网关。[S19]

## 会话策略

证书 TTL、Web session TTL、隧道绑定 ticket TTL、连接建立超时、空闲超时、SSH 最大会话时长是独立参数。管理员主动关闭应可审计；终端断开与用户登出是否关闭所有会话待确认。

撤销未来连接与关闭活跃会话分别验收；需要 KRL 时还要独立解决发布、权限、更新延迟和目标机应用状态。短期证书不是实时在线授权协议。

## 可观测性

记录注册/断线、权限通过/拒绝、ticket 消费、CA 申请成功/失败、Host Key 错误、认证阶段时延、active 会话数、各向字节数、退出原因、撤权命令及完成时间。session ID 放日志/trace，不作为高基数 metrics label。避免收集终端敏感内容作为普通错误上下文。

## 故障演练与容量

演练 CA 宕机、IdP 宕机、数据库/事件通道中断、Server 退出、Agent 重启、目标 sshd 重启、反向代理关闭空闲 WSS、证书/凭据轮换和主机时钟漂移。机器数、并发会话数、吞吐、代理超时和资源预算尚未提供，不声称某个单副本规模已验证。

## smux 专项

单用户撤权只关闭其 stream/SSH transport；不要调用整个 smux Session.Close。数据隧道故障影响该 Agent 的全部流，界面和告警应如实呈现。每 Agent 和全 Server 同时限制 active/pending streams、CA 签发并发和总体内存；smux 的共享接收预算不是平台总内存上限。控制通道单独使用 WSS，使数据应用队列不会直接阻塞控制消息，但两条连接仍共享物理网络带宽。
