# 01 产品规格

## 1. 范围与优先级

| ID | 需求 | 状态 |
|---|---|---|
| R01 | 多主机各运行 Agent，主动连接 Server | 用户明确 |
| R02 | Agent 通过 WebSocket 注册并接收建连请求 | 用户明确 |
| R03 | 按请求双向转发到机器上的 sshd | 用户明确 |
| R04 | Web 后台使用 OpenID Connect 登录 | 用户明确；具体 IdP 未定 |
| R05 | 展示在线主机/Agent，按 label 筛选 | 用户明确；过滤语法未定 |
| R06 | 连接时使用 step-ca 为用户签发 SSH 证书 | 用户明确 |
| R07 | 证书 TTL 很短，60 秒为举例目标，用于完成认证 | 用户明确；精确时钟边界未定 |
| R08 | 通过证书完成 SSH 会话并交互操作机器 | 用户明确 |
| R09 | 后台动态新增用户访问授权，不应要求重启主机 sshd | 用户明确的关注点 |
| R10 | 能集成到商业软件 | 用户背景；发行方式未定 |
| R11 | Server/Gateway 与 Agent 使用 Go | 用户最新明确 |
| R12 | sshd 反向转发通过 smux 多路复用 | 用户最新明确；在现有 WebSocket 上承载 |

## 2. 建议的 MVP 范围

采用 Server 作为 SSH 客户端、浏览器呈现 PTY、Agent 转发字节的实现基线。先支持已有 Linux 账号与交互 shell；每个连接独立证书和密钥；至少具备权限检查、主机身份校验、管理员断开、结构化连接审计和资源回收。

以下不是第一版必做：桌面 ssh-agent、原生 OpenSSH 直连、SFTP、端口转发、文件上传、自动创建 Linux 用户、全量终端录像、完整多租户隔离、跨副本透明迁移。用户尚未明确排除这些能力，后续可另立需求；不得在本次交接中把它们视为已承诺。

## 3. 用户流程

1. 用户完成 OIDC 登录，Server 建立自身 Web 登录会话。
2. Server 返回该用户可见的主机集合；label 过滤作用于授权后的集合。
3. 用户选择 host 与一个允许的 Linux 登录账号；不得通过请求任意指定地址/端口。
4. 创建会话请求，Server 再次校验权限及主机可用状态。
5. 浏览器连接该会话终端通道；Server 在 Agent 的常驻 smux 数据隧道上打开一条 stream，收到本机 sshd 拨号成功确认后，取得短期证书并完成 SSH 认证。
6. 终端支持字节输入输出、窗口大小变化、正常结束、错误展示和主动断开。

浏览器显示的 `allowed_login_users` 只是提示，不能替代创建、签发前和开始会话前的服务端检查。

## 4. 术语

- **后台用户**：由 OIDC `(issuer, subject)` 映射到稳定内部 user ID；不是 email 字符串对应的系统账号。[S15]
- **Linux 登录账号**：sshd 实际创建会话使用的账号，如 `ops`；本包不自动 provision 它。
- **主机 Agent**：WSS 反向隧道程序，不是 OpenSSH `ssh-agent`。
- **SSH 用户证书**：授权公钥以特定 principal 完成 SSH 用户认证，不是 X.509/TLS 证书。
- **SSH 主机身份**：Host Key 或 Host Certificate；与用于用户登录的 User CA 分开。
- **连接尝试**：一次 SSH transport/认证；**会话资源**：后台跟踪的连接实体；**SSH channel**：SSH transport 内的子通道。MVP 建议一个后台会话对应一个 smux stream、一个 SSH transport 与一个 PTY channel；smux stream ID 不等于业务 session ID，也不等于 SSH channel ID。

## 5. 产品层未决

用户可能共用 `ops`，也可能各自使用系统账号；是否允许 root、sudo、空闲超时、会话最大时长、断线保留、权限撤销是否立即踢出、录像和 SFTP 均未确认。不能用技术默认值替产品决策，见第 10 章。
