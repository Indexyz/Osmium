# Osmium

Web SSH 访问系统：用户通过 OIDC 登录，可以在浏览器终端里连接有权访问的主机，也可以用本机的 `ssh` 和 ssh-agent 连接。

每次连接时，Server 向 [step-ca](https://smallstep.com/docs/step-ca/) 申请一张约 60 秒的 SSH 用户证书，经由主机 Agent 的反向隧道连到 sshd。目标主机不需要开放入站端口，也不需要分发用户公钥。

## 快速开始

```sh
make build   # Server + CLI，约 9.4 MiB
make agent   # 目标主机上的独立 Agent，约 6.5 MiB；交叉编译：make agent GOARCH=arm64

osmium server -c server.json
osmium-agent  -c agent.json   # 在目标主机上运行

# 用户：本机 OpenSSH + ssh-agent
osmium login --server https://ssh.example.com
osmium ssh ops@host-123
```

配置示例见 [`examples/`](examples/)，完整步骤见 [部署文档](docs/deployment.md)。

## 文档

- [架构](docs/architecture.md)
- [部署](docs/deployment.md)
- [原生 SSH 客户端与 ssh-agent](docs/native-ssh.md)
- [开发与测试](docs/development.md)
- [默认决定与未实现功能](docs/decisions.md)
- [设计交接文档](docs/design/)

贡献前请阅读 [AGENTS.md](AGENTS.md) 中的实现约束。
