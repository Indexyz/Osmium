# 11 来源与许可说明

核对日期：2026-11-09。正文 `[Sxx]` 指向本页。公开文档和主分支是当日参考，不代表某个已部署版本；本包没有宣称完成版本兼容性验证。实施前锁定 release/commit，并保存对应配置和行为的测试证据。

## S01 · OpenSSH sshd_config 手册

https://man.openbsd.org/sshd_config.5

TrustedUserCAKeys、AuthorizedPrincipalsFile/Command 与配置权限。应复核目标发行版。

## S02 · OpenSSH auth2-pubkey.c

https://raw.githubusercontent.com/openssh/openssh-portable/master/auth2-pubkey.c

认证时读取 principals；Key ID 日志等。滚动源码，不是目标版本锁。

## S03 · OpenSSH sshkey.c

https://raw.githubusercontent.com/openssh/openssh-portable/master/sshkey.c

证书有效性检查与认证使用。

## S04 · RFC 4252 SSH Authentication Protocol

https://www.rfc-editor.org/rfc/rfc4252.html

认证成功后进入 SSH 连接服务；生命周期解释依据。

## S05 · step-ca SSH API 类型与处理

https://raw.githubusercontent.com/smallstep/certificates/master/api/ssh.go

publicKey、OTT、crt 的 JSON 字段与 SSH wire format 编码。

## S06 · Smallstep Provisioners

https://smallstep.com/docs/step-ca/provisioners/

JWK/OIDC/SSHPOP 的功能范围；注意开源与商业能力边界。

## S07 · Smallstep 配置说明

https://smallstep.com/docs/step-ca/configuration/

Provisioner claims 与用户 SSH 时长设置。

## S08 · step-ca JWK Provisioner 实现

https://raw.githubusercontent.com/smallstep/certificates/master/authority/provisioner/jwk.go

JWT step.ssh、subject/Key ID、audience 与签发约束。

## S09 · step-ca SSH options/validity 实现

https://raw.githubusercontent.com/smallstep/certificates/master/authority/provisioner/sign_ssh_options.go

ValidAfter/Before、default duration、backdate 与校验逻辑。

## S10 · step-ca 配置默认值实现

https://raw.githubusercontent.com/smallstep/certificates/master/authority/config/config.go

默认 backdate 与 claims；默认值需要按版本复核。

## S11 · Go SSH 包官方文档

https://pkg.go.dev/golang.org/x/crypto/ssh

NewClientConn、NewCertSigner、HostKeyCallback、PTY 等。

## S12 · coder/websocket 包文档

https://pkg.go.dev/github.com/coder/websocket

NetConn、read limit、deadline、context 行为。

## S13 · Smallstep SSH 模板说明

https://smallstep.com/docs/step-ca/templates/

模板字段、Sprig、toJson、默认扩展。

## S14 · Apache License 2.0

https://apache.org/licenses/LICENSE-2.0.html

商用、分发、通知、商标等许可条款。

## S15 · OpenID Connect Core 1.0

https://openid.net/specs/openid-connect-core-1_0.html

OIDC 身份、issuer/subject 与 ID Token 校验。

## S16 · step-ca API 路由

https://raw.githubusercontent.com/smallstep/certificates/master/api/api.go

/ssh/sign 路由；部署前缀按实际环境验证。

## S17 · Smallstep Provisioner claims 示例

https://smallstep.com/docs/step-ca/provisioners/#jwk

默认最短用户 SSH 时长与 JWK 配置示例。

## S18 · OpenSSH sshd 手册

https://man.openbsd.org/sshd.8

配置测试、配置重读与服务行为；具体服务名依发行版。

## S19 · OpenSSH certificate protocol

https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys

principal、有效期、critical options 与 source-address；实施前按所选版本核对。

## S20 · step CLI 许可证

https://raw.githubusercontent.com/smallstep/cli/master/LICENSE

项目当前主分支许可证：Apache-2.0。

## S21 · step-ca 许可证

https://raw.githubusercontent.com/smallstep/certificates/master/LICENSE

项目当前主分支许可证：Apache-2.0。

## 商业使用边界

核对的 step CLI 与 step-ca 主分支均使用 Apache-2.0，允许遵守条款的商业使用，包括闭源产品集成。分发时应处理许可证、适用的 NOTICE/归属声明、修改标注和商标边界，并审查实际构建的依赖许可证。[S14][S20][S21]

本包没有捆绑上述项目源码、二进制或第三方许可证全文，也没有为用户产品擅自指定许可证。最终发布物应基于锁定版本生成第三方清单；Smallstep 商业服务/商业平台的合同不由开源项目许可证自动覆盖。该说明不是对某个具体发行物的完整法律审查。

## 证据范围

技术事实来自上列官方文档/上游实现；接口路径、数据模型、ticket 设计、状态机、默认基线和任务拆分是本交接包的设计建议。不得把它们引用为上游 step-ca 或 OpenSSH 自带的完整平台能力。

## S22 · smux 官方模块与 API

https://pkg.go.dev/github.com/xtaci/smux@v1.5.57

Session、Stream、CloseWrite、角色与多路复用；参考模块固定该版本，不声称最新。

## S23 · smux v1.5.57 配置源码

https://raw.githubusercontent.com/xtaci/smux/v1.5.57/mux.go

默认 Version=1；本方案显式使用 Version=2，核对配置限制。

## S24 · smux v1.5.57 stream 源码

https://raw.githubusercontent.com/xtaci/smux/v1.5.57/stream.go

CloseWrite、deadline、Close、半关闭行为。

## S25 · coder/websocket v1.8.15 NetConn

https://raw.githubusercontent.com/coder/websocket/v1.8.15/netconn.go

共享 context、deadline、binary message 字节流与 ReadLimit 禁用。

## S26 · smux 许可证

https://raw.githubusercontent.com/xtaci/smux/v1.5.57/LICENSE

锁定版本 MIT；最终分发核验第三方通知。

## S27 · coder/websocket 许可证

https://raw.githubusercontent.com/coder/websocket/v1.8.15/LICENSE.txt

锁定版本许可证文件；实际打包依赖时核验。

本版增加 Go 参考代码和依赖版本声明，但不捆绑第三方库源码或二进制。上线前生成实际依赖 SBOM/许可证文件并检查安全通告；文档索引不是完成合规审查的证明。
