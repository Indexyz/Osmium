# 03 动态授权与 principal

## 1. 三层分工

**OIDC 证明身份；Server 判定资源访问；sshd 校验证书与本地账号规则。**

推荐授权函数的输入是可信的 `(user_id, host_id, login_user, action, current_policy_revision)`。用户 ID 来自登录会话，host 来自目录，login_user 必须在显式允许集合中。principal、Key ID、TTL 都由 Server 推导，而不是接受浏览器值。

## 2. 目标 principal，而非后台用户白名单

建议格式：

```text
tenant:<scope>:host:<immutable-host-id>:login:<linux-user>
```

`tenant` 是为隔离范围预留的示例前缀，不表示用户已要求多租户。单租户可使用固定 scope。标识符必须 canonicalize，拒绝分隔符注入、换行和空白；不要用可变 hostname、email 或显示名作为稳定主机身份。

`host-123` 的 sshd：

```sshconfig
PubkeyAuthentication yes
TrustedUserCAKeys /etc/ssh/user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

`/etc/ssh/auth_principals/ops`：

```text
tenant:t1:host:host-123:login:ops
```

Alice 的本次证书：Key ID 为 `user:u-alice/session:s001`；Bob 的本次证书：Key ID 为 `user:u-bob/session:s002`。两者的公钥、serial、会话不同，principal 可以完全相同。

Server 新增 Bob 的 `host-123/ops` 权限后即可为 Bob 签发证书。目标主机无需修改文件或重载。Key ID 用于审计关联，不是 OpenSSH 默认的后台用户授权规则。[S01][S02]

## 3. 哪些操作需要改主机

| 操作 | 目标主机动作 |
|---|---|
| 允许新后台用户登录已有 `host-123/ops` | 无；只改 Server 授权 |
| 撤销某后台用户的新连接权限 | 无；Server 拒绝创建/签发 |
| 修改已有 principals 文件内容 | 原子替换文件；新认证读取，不需 reload |
| 允许新 Linux 账号 `deploy` | 先保证系统有该账号及策略，再增加相应文件；本身不需 reload |
| 改 `AuthorizedPrincipalsFile` 指令或 `AllowUsers` 等 sshd 配置 | 检查后重新加载配置 |
| 终止已有 Web SSH 会话 | Server 关闭真实 SSH 连接与隧道；不是删 principal |

读取 principals 文件的认证路径会打开文件，因此文件应可被目标账号读取，建议 root:root、目录 0755、文件 0644，并禁止非管理员写入。发行版、SELinux/AppArmor、外部账户后端等需在目标环境检查。[S01][S02]

若未配置 principals 文件/命令，TrustedUserCAKeys 的通常行为会回到登录用户名匹配；不能认为自定义 `host:...` principal 会自行生效。必须用跨主机与跨账号负向测试证明配置正确。[S01]

## 4. AuthorizedPrincipalsCommand 可选方案

当不想每个 Linux 账号维护文件时，可以部署本地辅助程序，按 `%u` 输出允许 principal：

```sshconfig
AuthorizedPrincipalsFile none
AuthorizedPrincipalsCommand /usr/local/libexec/my-agent-principals %u
AuthorizedPrincipalsCommandUser ssh-principals
```

该程序根据受保护本机 host ID 和账号 allowlist 决定输出，不要把它做成“任意存在的账号都允许”。可以向本地 Agent 查询，查询失败必须拒绝。辅助程序由 root 拥有、不可被组/其他用户写入，使用专用低权限用户运行；上线前创建账号并检查访问权限。[S01]

这是可选路线，未确认采用。仅新增后台用户不需要它。文件与命令同时启用时不可想当然视为“两个条件都满足”；建议二选一，避免备用通道绕过授权。[S01]

## 5. 动态 label 与撤权

授权 label 与 Agent 自报 label 分开：`policy_labels` 由可信后台维护，`reported_labels` 只作展示/诊断。过滤结果不是权限证明。改 label 后应重新计算权限，并按已选策略影响已有会话。

撤权最小实现：立即拒绝后续连接/签发，取消尚未激活的尝试。若要求踢出当前会话，则向 owner 发出撤销事件并确认清理完成；设定可观测的完成时限与失败状态。不要从共享 principal 文件删除一行来只撤销 Bob——Alice 会一起受影响。

60 秒证书仍是有效期内可重复认证的凭证；短 TTL 仅缩小未部署额外在线检查/撤销机制时的风险窗口。CA 的撤销接口不会自动推送 OpenSSH KRL 到每台机器；如需此功能应单独设计。[S03][S04][S01]

## 6. 共享 Linux 账号的限制

principal 的主机限制只约束这张证书用于 SSH 认证的目标，不是系统会话沙箱。获得 shell 后的文件、进程和网络权限由目标 OS 控制。多人共享 `ops` 意味着相同 UID 权限，不能声称用户之间形成操作系统隔离。Key ID 和后台审计只能改善归因，不等于每人独立 OS 身份。
