# 配置示例使用说明

**所有配置均为片段/草案，不是生产配置；此次未启动 sshd 或 step-ca 验证。**

## sshd

`sshd/90-web-ssh-ca.conf.example` 只表达信任与 principal 映射。确认目标系统主配置支持 Include，再决定是否作为 drop-in；文件名不保证覆盖其他指令。`user_ca.pub` 必须是可信渠道取得的真实 SSH User CA 公钥，本包不提供假公钥。

`sshd/auth_principals/ops` 是 host-123 的示例；部署到其他机器必须替换 scope/host/account，不能给所有主机复制同一个 host ID。建议目标 `/etc/ssh/auth_principals` root:root 0755，文件 root:root 0644；不允许普通用户写入，同时确保账号认证路径可读。[S01][S02]

初次更改 sshd 指令需保留当前会话及应急通道，先 `sshd -t`，再检查账号对应的生效配置并 reload。只更新 principals 文件内容则无需 reload；推荐原子写入，避免写了一半的文件影响登录。Linux 账号应已存在且通过本机其他策略。

`command-alternative.conf.example` 只是可选机制说明，不包含 helper 实现，不可直接部署。不要把静态文件与命令方式当成两个必须同时满足的授权因子。

## step-ca

`step-ca/provisioner.fragment.json` 应合并进**专用 JWK Provisioner 对象**，不是整个 `ca.json`。JWK 类型/名称/公钥和 CA 的 SSH key 配置需要另行正确建立；不要把片段覆盖到生产配置根节点。

模板文件路径由部署环境解决。示例映射：`web-user.tpl` 放到所配置的 `templates/ssh/web-user.tpl`，`deny-x509.tpl` 放到 `templates/x509/deny.tpl`。合并时不要无意覆盖共享 Provisioner 的其他设置。

SSH 模板意图是拒绝 host 类型、要求一个 principal、仅开放 PTY。它没有检查后台用户权限，也没有实现 principal 格式/租户 policy，更不能保护已泄漏的 JWK 签发权限。X.509 模板意图是拒绝该 Provisioner 的 X.509 签发。必须对实际部署的签发路径、其他授权入口和固定版本做负向测试，不能只看到模板文件就认为权限已封闭。[S06][S13]

`min/default/max = 1m` 不代表整个证书有效区间必然只有 60 秒；backdate 和显式时间设置会影响结果。详见第 04 章。这里未修改全局 backdate，避免影响共享 CA。

没有包含 Agent mTLS 私钥、JWK 私钥、CA 密钥、OIDC client secret 或用户凭据。不要在测试配置中提交真实秘密。

引用索引见 `../docs/11-sources-and-license.md`。

## Go / smux

`transport.example.json` 是传输参数设计示例，不是已完成应用能直接加载的配置。smux version=2 是 wire 版本；依赖仍为 github.com/xtaci/smux。keepalive 和 stream/CA/SSH 的超时分开管理。
