# 部署

配置示例在 [`examples/`](../examples/)。

## 1. step-ca

按 [design/04-ca-integration.md](design/04-ca-integration.md) 新建一个专用的 JWK provisioner，例如命名为 `web-ssh`：
- 证书时长取 [provisioner.fragment.json](design/config/step-ca/provisioner.fragment.json)；
- SSH 模板用 [web-user.tpl](design/config/step-ca/web-user.tpl)，只允许一个 principal，只带 `permit-pty`；
- X.509 模板用 [deny-x509.tpl](design/config/step-ca/deny-x509.tpl)，禁止签发 X.509。

step-ca 默认会把证书的 `valid_after` 往前回拨 1 分钟（`ca.json` 中的 `authority.backdate`），所以一张“1 分钟”的证书，总有效区间是 120 秒，签发后剩余约 60 秒。如果需要更严格的窗口，可以把它调小，例如改成 `"5s"`。这个设置对整个 CA 生效，会影响该 CA 签发的所有证书。

Server 需要以下文件（对应 `ca.*` 配置项）：
- 该 provisioner 的加密 JWK 及其密码文件；
- step-ca 根证书；
- SSH User CA 公钥（`step ssh config --roots`），用来校验 step-ca 返回的证书。

## 2. 目标主机

在 sshd 中加入 [90-web-ssh-ca.conf.example](design/config/sshd/90-web-ssh-ca.conf.example) 里的配置，即 `TrustedUserCAKeys` 和 `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u`。然后为每个允许的登录名写 principal 文件，例如：

```
# /etc/ssh/auth_principals/ops
tenant:t1:host:host-123:login:ops
```

改动生产环境的 sshd 前，务必先评审合并后的配置，并保留应急访问方式。详见 [design/config/README.md](design/config/README.md)。

## 3. Agent mTLS

为每个 Agent 签发客户端证书，CN 必须与策略中的 `agent.client_cert_cn` 一致。生产环境请用自己的 PKI。本地试用可以用：

```sh
osmium dev pki -o dev/pki --server-hosts localhost,127.0.0.1 --agents agent-123
```

## 4. 策略

参考 [policy.example.json](../examples/policy.example.json)：
- `hosts`：每台主机需要填写
  - `ssh_host_keys`：必填，来自 `/etc/ssh/ssh_host_*_key.pub`；
  - `allowed_login_users`；
  - `policy_labels`；
  - 绑定的 Agent。
- `grants`：描述谁可以以哪些登录名访问哪些主机。主体可以是用户 ID、`issuer + subject` 或组；主机可以按 ID 或标签选择。
- `admins`：管理员可以关闭他人的会话，但不能观看。

修改策略文件后向 Server 发送 `SIGHUP` 即可热加载：
- 授权被撤销的活跃会话会立即关闭，可通过 `sessions.revoke_active` 关闭这一行为；
- 不需要改动主机。

## 5. 启动

```sh
osmium server -c /etc/osmium/server.json   # 参考 examples/server.example.json
osmium-agent -c /etc/osmium-agent/agent.json  # 目标主机上运行，参考 examples/agent.example.json
```

- 目标主机上应部署独立构建的 `osmium-agent`（`make agent`，交叉编译用 `make agent GOOS=linux GOARCH=arm64`）。它只包含 Agent 所需的代码，体积和内存占用都更小，适合性能和内存都有限的边缘设备。主程序里的 `osmium agent` 与它功能相同。
- 内存非常紧张的设备上，可以在 systemd unit 中设置 `Environment=GOMEMLIMIT=24MiB`，让 GC 在接近这个上限时更积极地回收。也可以在 `agent.json` 的 `smux` 中调小 `max_receive_buffer`（默认 4 MiB）和 `max_stream_buffer`（默认 256 KiB），以限制隧道缓冲。注意 smux 参数必须与 Server 配置完全一致。

- Server 的 Web 监听（`listen`）建议放在 HTTPS 反向代理之后，或直接配置 `tls_cert` / `tls_key`。
- `public_url` 必须是浏览器实际访问的地址，用于 Origin 校验。
- Agent 监听（`agent_listen`）强制 mTLS。
- 审计日志写入 `audit.dir`（必填），见下文“审计”。

## 6. 审计

审计事件只包含元数据：用户、动作、结果、主机/登录名、会话 ID、策略版本、证书序列号和密钥指纹，不包含令牌、ticket、私钥或终端内容。每条事件有两个用户字段：
- `actor`：稳定的内部 ID（`user:u-…`），由 OIDC 的 issuer 和 subject 派生；
- `user`：IdP 提供的显示名，只用于展示和检索，不参与授权。

### 本地存储（默认）

- 事件追加写入 `audit.dir` 下的分段文件 `YYYY-MM-DD/HHMMSS.nnnnnnnnn-<server_id>.jsonl`，每行一个事件。每个 UTC 日至少一个分段，Server 每次启动都会新开一段。
- 目录权限为 0700，文件为 0600。该目录应只用于审计，不要与其他数据混放。
- `audit.retention`（例如 `"2160h"`，即 90 天）到期后按整日删除；不设置则永久保留。
- `audit.stdout: true` 会同时把每条事件写到 stdout，便于 journald 或日志采集器收集。

### S3 兼容存储（AWS S3、MinIO、RustFS）

配置 `audit.s3` 后，`audit.dir` 就只作缓冲：事件仍先写本地分段，分段封口后 gzip 上传，上传成功才删除本地副本。

```json
"audit": {
  "dir": "/var/lib/osmium/audit",
  "retention": "2160h",
  "s3": {
    "endpoint": "https://rustfs.internal:9000",
    "bucket": "osmium-audit",
    "prefix": "prod",
    "region": "us-east-1",
    "access_key_id": "osmium-audit",
    "secret_access_key_file": "/etc/osmium/s3-secret",
    "segment_interval": "5m",
    "segment_max_bytes": 8388608
  }
}
```

- 对象名是 `<prefix>/YYYY-MM-DD/HHMMSS.nnnnnnnnn-<server_id>.jsonl.gz`，可以直接下载后用 `zcat` 查看。不同 `server_id` 的对象互不冲突，多个 Server 可以共用一个前缀。
- 寻址方式：AWS 的域名用虚拟主机风格，其他 endpoint（MinIO、RustFS）用路径风格，无需额外配置。自签证书的 endpoint 可通过 `ca_file` 指定 CA。
- 凭据：
  - 设置 `access_key_id` 时，必须同时设置 `secret_access_key_file`，配置文件里不写明文密钥。
  - 都不设置时，依次使用环境变量 `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`、`MINIO_ACCESS_KEY`/`MINIO_SECRET_KEY`，最后使用 IAM 角色。
- 权限：bucket 需要事先建好，Server 启动时会检查它是否存在。凭据需要 `s3:ListBucket`、`s3:GetObject`、`s3:PutObject`；如果配置了 `retention`，还需要 `s3:DeleteObject`。
- 封口：分段写满 `segment_interval`（默认 5 分钟）或 `segment_max_bytes`（默认 8 MiB）时封口，跨过 UTC 零点也会封口。没有新事件时，后台每隔最多 30 秒检查一次，到期也会封口。因此只存在本地的事件，最多是最近约 5.5 分钟内写入的。
- 故障：S3 不可用时，事件继续写本地，并记录错误日志，恢复后自动补传。Server 正常退出时会尝试最后上传一次；没传完的分段（包括崩溃时留下的）会在下次启动时上传。
- 保留：`audit.retention` 同时作用于 S3，Server 每小时清理一次过期的日期目录。也可以不设置，改用 bucket 的生命周期规则。
- 不做防篡改：有写权限的人可以改写或删除对象。

### 查询

管理员使用 `GET /api/v1/admin/audit`，本地未上传的分段和 S3 上的对象会合并查询。参数如下：

| 参数 | 说明 |
| --- | --- |
| `from`、`to` | RFC 3339 格式，左闭右开，默认最近 24 小时，跨度最多 31 天 |
| `user` | 显示名（不区分大小写）或内部用户 ID（不带 `user:` 前缀） |
| `actor`、`action`、`session_id`、`target` | 精确匹配 |
| `limit` | 1–1000，默认 100 |
| `cursor` | 上一页返回的 `next_cursor` |

结果按分段起始时间排序，同一分段内按时间排序。单次请求最多从 S3 读取 64 个对象，读到上限后返回 `next_cursor`。所以一页可能不满 `limit`，甚至为空，但只要 `next_cursor` 不为空，就应继续翻页。

非管理员访问返回 403，参数非法返回 400。

step-ca 自身的日志会以 info 或 warn 级别记录一次性令牌（OTT）和完整证书。OTT 是一次性的，有效期也很短，但仍应限制 step-ca 日志的访问权限。
