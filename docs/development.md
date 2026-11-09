# 开发

## 构建

```sh
make build                        # 发布构建，输出 ./osmium
make size                         # 构建并打印体积
go build -o osmium ./cmd/osmium   # 调试构建（保留符号表，体积大）
./osmium --help
```

`make build` 等价于：

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always --dirty)" -o osmium ./cmd/osmium
```

## 二进制体积

linux/amd64、Go 1.26 下的参考数据：

| 构建方式 | 大小 |
| --- | --- |
| `go build`（默认） | 约 13.7 MiB |
| `make build`（`-trimpath -s -w`） | 约 9.4 MiB |
| 再用 `upx --best --lzma` 压缩（可选，默认不做） | 约 3.0 MiB |

- `-s -w` 去掉符号表和 DWARF。`.gopclntab` 会保留，panic 时仍有栈回溯。
- **不要在程序中使用 `text/template` 或 `html/template`**，cobra 自带的帮助模板不受影响。模板引擎通过反射按名字查找方法，导致链接器必须保留所有可达类型的导出方法，体积会增加约 2 MiB。出于同样的原因，CLI 授权页用手写 HTML 生成，所有动态值都经过 `html.EscapeString` 转义。`reflect.Value.MethodByName` 也有同样的问题，应当避免。
- 排查体积时可以用两条命令：
  - `go tool nm -size -sort size osmium`：按大小列出符号。
  - `go build -ldflags=-dumpdep ./cmd/osmium 2>&1 | go run github.com/aarzilli/whydeadcode@latest`：没有输出才说明方法裁剪仍然生效。
- UPX 压缩的代价：启动时占用更多内存，多个进程之间不能共享代码页，部分安全软件会误报。因此只建议作为可选的分发产物。如果只是想减小下载体积，用 `xz -9` 打包即可，约 3.0 MiB。

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
