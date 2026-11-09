# 开发

## 构建

```sh
go build -o osmium ./cmd/osmium
go build -ldflags "-X main.version=v0.1.0" -o osmium ./cmd/osmium   # 注入版本号
./osmium --help
```

## 测试

```sh
go test -race ./...
go test -short ./...          # 跳过端到端测试
E2E_LOG=1 go test -run TestShellOverSharedTunnel -v ./internal/e2e/   # 输出日志与审计
```

端到端测试（`internal/e2e`）需要 PATH 中有 `sshd`、`ssh`、`ssh-agent`、`ssh-add`。它会：
- 以当前用户身份，在回环地址的随机端口上启动无特权 sshd；
- 用进程内的假 step-ca（`internal/ca/catest`）签发证书；
- 原生模式测试会编译 `osmium` 二进制，走完 `login` → 浏览器确认 → `ssh` 的完整流程。

测试不会改动系统里的 sshd，也不会读取开发者的 `~/.ssh`。覆盖的场景对应 [design/09-acceptance-tests.md](design/09-acceptance-tests.md)。

## 本地登录

在 server 配置里设置 `"dev_login": true` 可以不用 OIDC，然后访问 `/auth/dev-login?user=alice&group=ops`，用户的 issuer 为 `dev`。**生产环境禁止开启。**

`osmium dev pki` 用于生成本地使用的 Agent mTLS 证书。
