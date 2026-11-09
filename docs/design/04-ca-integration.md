# 04 step-ca 签发集成

## 1. 建议授权模型

OIDC 登录由 Server 校验并转成内部用户身份。每次连接由 Server 重新做资源授权，然后通过专用 JWK Provisioner 申请 SSH 用户证书。step-ca 在此信任 Server 的授权判断；不是独立验证后台每一条角色/label 规则。

JWK 私钥不是 CA 的 SSH 签名私钥，但具有强签发权限，必须隔离存储。JWK Provisioner 原生能力不限于本业务的 SSH 用户证书，不能仅因名字叫 `web-ssh` 就认定其无法签 Host 或 X.509 证书。应配合模板、网络暴露范围及必要的额外验证限制，并用负向测试证明。[S06][S08]

OIDC ID Token、Web 登录会话、JWK OTT、Agent 隧道绑定 ticket、SSH 证书分别管理，不相互冒充。此架构不依赖浏览器每次重登，也不把最初的 ID Token 当作长期万能签发凭据。

## 2. 签发流程

1. 确认本次 host、login_user、session、attempt、策略版本和 Agent epoch。
2. 生成本次临时 SSH 密钥；生成规范的单个目标 principal 和审计 Key ID。
3. 签发短时 JWK provisioning JWT：正确 `iss`、`aud`、`sub`、时间声明、唯一 `jti`、正确 `kid`；`step.ssh` 绑定类型、principal、期限等。
4. 通过验证 CA TLS 身份的 HTTPS 调用 `/ssh/sign`。
5. 解码响应证书并检查返回字段；只有满足预期才进入 SSH 认证。

JWK 的 `sub` 与 Key ID 应使用一致的规范值；不要凭印象手写不同的 token 结构。`aud` 必须与部署 CA 接受的 SSH 签发 audience 相符，涉及反向代理时尤其要验证。[S08]

## 3. wire format 与接口

以下为说明结构的伪值，不是可直接发送的有效证书请求：

```json
{
  "publicKey": "<Base64(SSH public key wire bytes)>",
  "ott": "<signed SSH provisioning JWT>",
  "certType": "user",
  "keyID": "user:u42/session:s789",
  "principals": ["tenant:t1:host:host-123:login:ops"],
  "validBefore": "60s"
}
```

响应的 `crt` 为 Base64 编码的 OpenSSH certificate wire bytes；不是 X.509 PEM，也不是整行 `ssh-ed25519 ...` 公钥文本。解码后按 SSH 公钥/证书类型解析，再配对临时私钥。`/ssh/sign` 的部署路径前缀需以实际路由验证。[S05][S16]

返回验证至少包括：用户证书类型、证书公钥等于本次公钥、预期 User CA 签名/信任、精确 principal 集合、Key ID、有效期边界、允许的 critical options/extensions。响应不符即失败并记录脱敏错误；不能因为 HTTPS 成功就省略字段检查。

## 4. 60 秒的准确含义

step-ca 默认最短 SSH 用户证书时长为 5 分钟；专用 Provisioner 需要下调。包内示例设置 min/default/max 为 `1m`。[S07][S17]

**该 claims 片段不是“密码学上严格只可用 60 秒”的完整证明。** 核对的实现中默认 backdate 为 1 分钟；有效期校验考虑 backdate，`maxUserSSHCertDuration` 不能脱离 `ValidAfter/ValidBefore` 和该版本实现单独解读。[S09][S10]

需要区分：

- `valid_before - CA签发时刻`：还剩多少时间可完成认证；建议产品以“约 60 秒”描述。
- `valid_before - valid_after`：证书记录的完整时间区间，可因 backdate 大于 60 秒。
- 目标 sshd 当前时间：实际是否接受认证取决于目标时钟。

如果业务要求严格总区间 60 秒，必须另行决定 backdate、显式绝对时间及目标时钟误差预算；不能直接照搬当前片段。显式 `ValidAfter` 和默认 `ValidAfter` 的处理可能不同，需对固定版本实测。不要为一个业务轻易修改共享 CA 的全局 backdate。

## 5. 认证后行为

OpenSSH 在用户认证路径检查证书有效期；通常不会因用户证书到期自动结束已经建立的 SSH transport。相同连接内打开新 channel 也不是重新执行那次用户证书认证，因此网关仍需独立限制 channel 类型/数量及总会话时长。[S03][S04]

此方案不对活跃会话做“用户证书续期”；新连接重新授权和签发。证书本身不提供首次使用后销毁语义，不能用它代替一次性 data ticket。[S03][S06]

## 6. 签发失败与重试

CA 不可用时拒绝新连接，不回退到密码、长期共享私钥或永久证书。已有已认证连接原则上不因 CA 暂时不可用而自动重建。

请求超时可能发生在证书已签发之后；不盲目复用同一 OTT 或循环签发。先使原尝试失效并关闭通道，按幂等/重试策略重开；新的尝试使用新的 attempt ID、密钥及授权 token。证书/私钥不得返回浏览器。

## 7. 参考实现路线

实现已选择 Go：用 `ssh.NewCertSigner` 配对证书与 signer，`ssh.NewClientConn` 在已完成 open/ack 的 smux stream 上执行握手；HostKeyCallback 必须校验所选目标身份。[S11]

`github.com/coder/websocket.NetConn` 只作为共享 smux Session 的底层适配，不能直接占用它执行某个 SSH 握手。每个 SSH client 独占自己的 stream。取消/截止时间应按层隔离，详见协议与 Go 实现章节。[S12][S22]
