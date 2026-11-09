# 08 实施任务与交付门槛

Go 与 smux 已确定。没有现成用户仓库，不指定实际 issue 编号或已存在包路径。以下为本地待办，不给未经验证的工期估计。

## M0：真实 CA/sshd 互操作

两个不同 host identity 的隔离 sshd + 测试 step-ca。验证 60 秒与 backdate、wire format、目标 principal、证书过期后旧连接继续而新认证失败、动态增加 Bob 不改主机、principals 文件动态读取、模板拒绝非预期类型。固定版本并保留脱敏证据。未通过不要以 UI 完整替代核心正确性。

## M1：身份、主机目录与授权

OIDC `(issuer,sub)`、Web session、注册绑定、可信/上报 label 分离、登录账号 allowlist、列表与连接 API 授权、审计。UI 筛选不是权限；每次建连检查最新状态。

## M2：Go + WSS + smux 数据层

2a 控制 WSS mTLS、hello/welcome/heartbeat、owner/epoch 和短期隧道 ticket。
2b 常驻数据 WSS、NetConn、smux v2，Gateway client/Agent server；ready 状态。
2c stream.open/open_result 精确长度 framing、绑定检查、pending 配额、固定 TCP dial。
2d 双向 io.Copy、CloseWrite + 有界 drain、deadline/context 分层、局部取消和完整回收。
2e 并发多流、旧 epoch、重复 ticket/attempt、慢流、恶意报头、共享隧道中断；验证关流不关隧道。

输出：可复现的多流传输测试、resource/FD/goroutine 检查。参考 `reference/go` 不是 M2 已完成的声明。

## M3：Go CA 客户端和 SSH

临时密钥、JWK OTT、HTTPS CA API、返回字段验证、Host Key callback、在 smux stream 上调用 ssh.NewClientConn、PTY/shell。仅在 TCP ack 后签发。签发前/激活前重查授权，CA 不可用 fail closed。握手超时只作用对应 stream。

## M4：Web 终端与生命周期

状态通知、binary I/O、resize/exit/close、Origin/CSRF、session 归属、幂等 API、浏览器断线策略。会话关闭不得断开同 Agent 的其他用户。

## M5：撤权、运维、发布

关闭 pending/active 任务、owner 回执、重启 reconcile、凭据/CA/Host Key 轮换、指标审计、容量与漏洞/许可检查。多副本需要实测路由与 epoch fencing，不默认透明迁移。

## 首批任务草案

I01 CA/sshd 互操作；I02 OIDC/授权；I03 控制 WSS 注册；I04 常驻数据 WSS/smux 和 stream 协议；I05 CA 签发与 SSH 验证；I06 Web 终端；I07 撤权/取消/资源回收；I08 容量、安全和发布。

Go 包拆分建议见第 12 章。各阶段验收对应第 09 章，不用依赖下载失败的本地参考测试替代真实系统测试。
