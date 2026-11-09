# 02 架构与连接生命周期

**Go、WebSocket、smux 是明确需求；双通道布局和其余实现细节是建议基线。**

## 1. 组件与职责

| 组件 | 职责 | 边界 |
|---|---|---|
| 浏览器 | OIDC 跳转、主机目录、终端输入输出、resize | 不持有 SSH 私钥或 CA 凭据 |
| Go Web API / 授权 | 登录会话、目录、policy、审计、会话 API | 不信任浏览器传来的 principal/label 权限 |
| Go SSH Gateway / owner | 临时密钥、CA 签发、目标主机验证、SSH 客户端和 PTY | Server 可见终端明文 |
| Go Agent Manager | 控制 WSS、mTLS 身份、presence、epoch、数据隧道绑定 | owner/epoch 隔离旧连接 |
| Go Agent | smux accept、受控本机 TCP dial、双向 io.Copy、资源清理 | 不做 OIDC，不持签发密钥，不解析 SSH |
| step-ca | 验证 Provisioner 授权并签发 SSH 用户证书 | 不理解应用的 label/角色规则 |
| 本机 sshd | 验证 User CA、principal、期限与账号策略 | 不同步后台用户名单 |

第一版逻辑组件可在同一 Server 进程中。前端框架、数据库、部署规模未确定。

## 2. 连接分层

```text
Browser ←终端 WSS→ Gateway 的 SSH client
                           │ SSH 字节
                   smux Stream #N (net.Conn)
                           │
                   smux Session (version 2)
                           │
              websocket.NetConn(binary) / WSS
                           │
                   Agent smux Session
                           │
                     smux Stream #N
                           │ open/ack 后 io.Copy
                     TCP 127.0.0.1:22
                           │
                          sshd
```

Agent 主动建立两条 WSS：`/agent/v1/control` 是控制 JSON，`/agent/v1/data` 是共享 smux 数据隧道。建立数据 WSS 时用短期一次性 **隧道绑定 ticket**；之后不是每个 SSH stream 再建 WSS。

Gateway 执行 `smux.Client` 并 `OpenStream`，Agent 执行 `smux.Server` 并 `AcceptStream`。物理 TCP/WSS 由 Agent 发起不妨碍这个 smux 角色分配。stream 实现 `net.Conn`，可供 Go SSH 客户端使用。[S11][S22][S23]

## 3. 机器上线

1. Agent 用可信机器凭据建立控制 WSS，发送 hello；Server 将认证身份映射到固定 agent/host，分配 epoch。
2. welcome 返回已绑定 host/agent/owner/epoch 的短期 data ticket、data_tunnel_id、相对数据路径。
3. Agent 以同一身份建立数据 WSS；Server 原子消费 ticket。双端启动 smux v2。
4. 控制连接活跃且数据 smux session 可用后，主机才标记 `ready`；只有 heartbeat 并不代表可建立 SSH。

单 epoch 基线只允许一个数据隧道。数据隧道失效后结束旧会话并重新注册产生新 epoch；不把新 WSS 伪装为原 Session 续接。实现顺序/缓冲由第 05 章定义。

## 4. 用户连接顺序

```text
OIDC 登录 → 选择 host/login → POST 创建会话 → 浏览器绑定终端 WSS
  → 权限/ready/owner/epoch 检查
  → Gateway OpenStream
  → stream.open 帧（session/attempt/host/epoch）
  → Agent 校验绑定/幂等/配额，TCP dial 本机 sshd
  → stream.open_result(ok=true)
  → Gateway 重查权限，生成临时密钥并签发约 60 秒用户证书
  → 校验返回证书，清理握手 deadline，建立 SSH transport
  → 校验目标 Host Key，证书用户认证
  → 激活前检查取消/撤权，PTY + shell → active
```

业务报头只在每条 stream 的开头出现；ack 之后绝不插入 JSON。Agent 可以在此时从 sshd 读到 SSH banner，转发必须保留这些字节，不得让 JSON decoder 预读并丢弃。

sshd 的未认证连接在等待 CA 签发时仍受它的登录超时和未认证连接数量限制。CA timeout 与 Gateway 握手期限必须在目标配置内留余量；压测包括“慢 CA + 大量 pending streams”，不能靠无限增大 sshd 限额掩盖问题。[S01]

## 5. 状态与私钥

会话：`created → waiting_agent → signing → ssh_authenticating → active → closing → closed`，不可恢复错误转 `failed`。`waiting_agent` 包含 stream open/ack，绝非“仅控制消息送达”。`signing` 只有在 ack 成功后进入。

每次尝试独立临时 key，只在 Gateway 内存中使用。数据库只记录证书 serial、Key ID、公开指纹和期限，不保存私钥/OTT。取消/撤权/失败后清理连接与引用；不要承诺 Go GC 下绝对内存清零。

策略检查在创建、签发前和激活前进行；进入 closing 后不得再开 shell。最终状态只落一次，清理幂等。记录 state_version，妥善处理撤权与建连竞争，不能承诺零传播延迟。

## 6. 加密和身份

浏览器至 Server 是 HTTPS/WSS；SSH 的端点是 Gateway 与目标 sshd，而非浏览器。Server 可读终端并代用户操作，必须在产品信任模型中说明。

Agent 只拨本地可信配置地址。Host Key 由可信注册渠道 pin；变化不自动接受。mTLS Agent 身份不能替代 SSH Host Key 验证。主机重装/密钥轮换需要独立可信流程。[S11]

## 7. 故障域和多副本

正常关闭某用户会话：关闭 SSH channel、SSH transport、对应 stream/TCP；不关闭共享 smux Session。数据 WSS/smux Session 故障：该 Agent 上所有依赖此 Session 的 SSH transport 失败，不能迁移原字节流。

建议控制 WSS 断开也关闭该 epoch 的数据隧道，避免失去管理能力的孤立会话；这是需确认的产品基线。浏览器断开是否立即结束 SSH 仍待确认。

多副本须把控制 WSS、数据 WSS 和对应 SSH owner 绑定到正确进程。元数据至少包含 owner_server_id、epoch、data_tunnel_id、lease。共享数据库不是 socket 共享；旧 owner 消息不得影响新 epoch。不得让 mTLS Agent 盲跟任意重定向并泄漏 ticket。
