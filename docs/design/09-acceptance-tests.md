# 09 验收与测试矩阵

**本章是需要实现并运行的测试，不表示已经通过。** 此次交付实际执行的检查结果见根目录 `VALIDATION.md`。

## A. 认证与动态授权

| ID | 操作 | 预期 |
|---|---|---|
| A01 | Alice 有 host-123/ops 权限 | 获得精确 principal，成功连接 |
| A02 | Bob 无权限但手工请求连接 API | 拒绝；不签发，不开 shell |
| A03 | 后台添加 Bob 权限后重试 | 成功；主机配置文件和 sshd 进程无需变更 |
| A04 | 撤销 Bob；Alice 仍有权限 | Bob 新连接拒绝；Alice 不受影响 |
| A05 | 同证书连接 host-456 的 ops | 目标 principal 不匹配，认证失败 |
| A06 | 同证书在 host-123 登录 root/deploy | 除明确合法对应授权外拒绝 |
| A07 | 后台用户 ID 与 Linux 账号不同 | 按目标账号与 principal 认证，不要求同名 |
| A08 | 修改 principals 文件并立即发起新认证 | 新内容生效，无 reload；旧已建立连接不因此自动关闭 |
| A09 | 只有后台用户存在，没有目标 Linux 账号 | 登录失败，不自动创建账号 |
| A10 | 伪造 Agent reported_labels 提升权限 | 不改变 policy_labels，不授予权限 |
| A11 | UI 列表过滤后直接请求不可见 host | 服务端仍拒绝 |
| A12 | 相同 sub、不同 OIDC issuer | 不是同一内部安全身份 |

## B. 证书与 CA

| ID | 操作 | 预期 |
|---|---|---|
| B01 | 按 60 秒目标签发 | 实测并记录 valid_after/before、签发时钟与 backdate；符合选定语义 |
| B02 | 有效期内完成认证，等待超时 | 已建连接保持，除非另有会话策略 |
| B03 | 证书到期后新建 SSH 连接 | 拒绝；不能因已有会话活跃就复用过期认证 |
| B04 | 有效期内持同证书私钥再次认证 | 证书层可能接受；证明不是一次性。应用必须禁止跨尝试复用 |
| B05 | CA 返回不匹配公钥/Key ID/principal/type | Gateway 检查失败，不尝试使用 |
| B06 | 请求 host 证书或 X.509 | 专用签发边界拒绝；验证实际模板与版本，不仅检查 UI |
| B07 | 浏览器提交自选 principal/TTL/token | 请求拒绝或不存在这些输入字段 |
| B08 | 不同签发 CA、过期或未到生效时间 | 认证拒绝 |
| B09 | 目标时钟快/慢、显式/默认 ValidAfter | 对所选误差预算有明确成功/失败结果 |
| B10 | CA 请求超时但可能已签发 | 无无限重试、无 OTT 盲重放；原尝试失效并回收 |
| B11 | CA 离线 | 新连接失败；不降级到密码/共享长期 key |
| B12 | 同 transport 申请额外 SSH channel | 由 Gateway/服务端策略限制，不误认为会重新检验证书 TTL |

## C. 隧道与主机身份

| ID | 操作 | 预期 |
|---|---|---|
| C01 | Agent 主动 WSS 注册、心跳 | 正确绑定主机身份与 owner/epoch |
| C02 | 未认证客户端冒充 Agent | 拒绝 |
| C03 | 两个数据连接竞争同 ticket | 最多一个成功；不替换已有 socket |
| C04 | 隧道 ticket 过期/错 Agent/host/tunnel/epoch | 拒绝，记录脱敏原因 |
| C05 | 旧控制连接迟到 close 或旧数据连接的 stream.open | 不影响新 epoch 的会话 |
| C06 | 数据通道发送 text JSON | 协议错误并关闭；不作为 SSH 数据 |
| C07 | 任意目标地址/URL 注入 | 不发生非配置目的拨号 |
| C08 | Host Key 与登记不同 | 失败；不得静默接受新 key |
| C09 | Agent mTLS 有效但 sshd 主机身份错误 | 仍拒绝 SSH |
| C10 | sshd 拒绝 TCP、WSS 中途断开 | 清理所有资源，状态可解释 |
| C11 | 正常退出有末尾输出 | 有界 drain 后结束，不无条件截断 |
| C12 | 超大帧、慢对端、并发耗尽 | 有限资源、背压/配额明确、无无限缓冲 |

## D. Web 会话与撤权

| ID | 操作 | 预期 |
|---|---|---|
| D01 | 用户知道他人的 session ID | 不能 attach、查看敏感状态或关闭 |
| D02 | 非信任 Origin 发起带 cookie WSS | 拒绝 |
| D03 | 重复 Idempotency-Key 同请求/不同请求 | 同请求返回原资源；不同请求冲突 |
| D04 | shell 尚未 active 时发输入 | 拒绝或有界丢弃，绝不向未授权会话执行 |
| D05 | resize 边界/畸形控制 JSON | 正常值应用，异常拒绝，不崩溃 |
| D06 | 连接期间管理员撤权 | 按已确定策略取消 pending 并关闭 active，报告完成结果 |
| D07 | 撤权发生在签发与开 shell 之间 | 激活前检查拦截；关闭连接 |
| D08 | 浏览器断开/登出 | 按已确认策略执行，不能隐式无限保留 |
| D09 | 用户通过 shell 启动脱离终端的后台进程后断开 | 不宣称自动杀死所有远端进程；验证产品约定 |

## E. 部署、审计与可靠性

| ID | 操作 | 预期 |
|---|---|---|
| E01 | Server/Agent 重启 | 无伪 active 记录；不伪装恢复原 SSH transport |
| E02 | 多副本 LB 到错误 owner | 安全路由或明确拒绝；不跨 user/host 配错通道 |
| E03 | owner 失去租约、事件总线故障 | 不继续无约束接新连接；撤权状态可观测 |
| E04 | User CA/Agent 凭据/Host Key 轮换 | 有部署顺序、旧信任移除和回滚策略 |
| E05 | 搜索应用/代理日志、trace、快照 | 无私钥、OTT、data ticket、OIDC token 明文 |
| E06 | 同 Linux 账号的两个后台用户登录 | user_id/session/key_id/serial 可区分追溯 |
| E07 | 连续建连与各种错误循环 | FD、任务、内存和数据库状态无持续泄漏 |
| E08 | 修改配置初次上线 | `sshd -t` 与生效配置检查通过，保留应急通道 |

最少在两个不同 host identity 的目标实例上做跨主机负向测试；仅在一台机器成功登录不足以证明 principal 约束有效。


## F. Go / smux 专项（需实际集成验证）

| ID | 操作 | 预期 |
|---|---|---|
| F01 | 两条 SSH 同时使用同 Agent | 只复用一个数据 WSS，两个独立 smux streams |
| F02 | 关闭/撤销其中一个用户 | 其 TCP/SSH/stream 结束，另一条仍可交互 |
| F03 | 一条 stream 的 open 或 SSH 握手超时 | 只失败该流，共享 NetConn/Session 不关闭 |
| F04 | 断开数据 WSS | 该 Session 所有 SSH 连接失败，无透明恢复旧流 |
| F05 | 两端 smux 版本不一致 | 拒绝/失败并报告；异步检出时撤回 ready，不继续承载新建连 |
| F06 | JSON ack 后紧跟 SSH banner | 不丢字节，不让 JSON decoder 预读 banner |
| F07 | 零长/超长/截断/未知字段报头 | 有界拒绝，不无限分配，其他流仍可用 |
| F08 | smux stream.Open 指向不同 host/旧 epoch | 拒绝且不拨号 |
| F09 | TCP 半关闭后仍发送末尾响应 | 反向输出被 drain，超时可清理 |
| F10 | 取消发生在 TCP dial、CA 签发或 active | 对应 context 清理，无 orphan 连接 |
| F11 | 快速流 + 不读输出的慢流 | 资源受限；记录延迟，不宣称 TCP HOL 被消除 |
| F12 | 应用 stream 并发超配额 | 拒绝额外 pending，已有流继续 |
| F13 | 同 session/attempt 重复 open | 原子拒绝重复，不替换现有 stream |
| F14 | 将控制消息误写入已 ack 的流 | 不作为业务控制执行；SSH 错误并仅关闭该流 |
| F15 | 阶段 deadline 清除后持续会话 | 不因遗留 10s/60s deadline 被误杀 |
| F16 | 新 epoch 重连后旧 close 到达 | 新 epoch 会话不受影响 |
| F17 | 长期空闲无业务流 | 按 keepalive 和代理 timeout 正确保活/失效 |
| F18 | go test -race、并发开关与慢网压测 | 无数据竞争；FD/内存/goroutine 预算明确 |
| F19 | CA 延迟 + 大量已经 TCP dial 的 pending | 不耗尽 sshd 未认证连接；超时回收且不无限排队 |
