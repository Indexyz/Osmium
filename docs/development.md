# 开发

## 构建

```sh
make web                          # 构建 React + ghostty-web 前端到 web/dist
make build                        # 构建前端并发布构建 Server + CLI，输出 ./osmium
make agent                        # 独立 Agent，输出 ./osmium-agent（可加 GOOS/GOARCH/GOARM 交叉编译）
make size                         # 构建两者并打印体积
go build -o osmium ./cmd/osmium   # 调试构建（保留符号表，体积大；复用已有 web/dist）
./osmium --help
```

### 容器构建

仓库根目录的 [Dockerfile](../Dockerfile) 采用多阶段构建（Node 构建前端 + Go 原生交叉编译 + `distroless:nonroot` 运行时），提供 `server`（默认）与 `agent` 两个 target：

```sh
docker build -t osmium:dev --target server .
docker build -t osmium-agent:dev --target agent .
```

### 版本管理与发布（Changesets）

本仓库使用 [Changesets](https://changesets.dev/) 管理语义化版本与 `CHANGELOG.md`（配置位于 `.changeset/config.json`）：

```sh
npm install           # 安装根目录 Changesets CLI
npm run changeset     # 新增一条变更记录（.changeset/*.md），随 PR 一并提交
```

合并 PR 到 `main` 后，`.github/workflows/release.yml` 会自动维护 **Version Packages** PR；合并该 PR 后自动打 `vX.Y.Z` tag、创建 GitHub Release、推送 `ghcr.io/indexyz/osmium` 与 `ghcr.io/indexyz/osmium-agent` 多架构镜像，并上传多平台二进制归档与校验和。

> GitHub 仓库需在 **Settings → Actions → General → Workflow permissions** 中开启 **Read and write permissions** 与 **Allow GitHub Actions to create and approve pull requests**，否则 `changesets/action` 无法自动创建发版 PR。

前端开发（在 `web/` 目录下，使用 Vite 热更新并代理 `/api` 和 `/auth` 到本地 `127.0.0.1:8080`）：

```sh
npm --prefix web install
npm --prefix web run dev          # 前端开发服务器
npm --prefix web test             # Vitest 单元测试
npm --prefix web run build        # 类型检查并生成 web/dist
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
| `make agent`（独立 Agent） | amd64 约 6.5 MiB，arm64 约 6.1 MiB，armv7 约 6.4 MiB |

**独立 Agent（`cmd/osmium-agent`）是对体积要求最严格的产物**，它运行在性能差、内存小的边缘设备上。约束如下：

- 只依赖 `internal/agent`、`internal/tunnel`、`internal/protocol`、`internal/config`，不要引入 cobra、Server、CLI、OIDC、SSH 客户端或模板相关的包。命令行参数用标准库 `flag` 解析。
- 这几个包里不要用 `regexp`，ID 和错误码的校验都是手写的（见 `tunnel.ValidID`）。
- 剩下的体积主要来自 Go 运行时、TLS，以及 websocket 库所需的 `net/http`。空闲时常驻内存约 7.5 MiB（amd64）。
- 修改上述包后，运行 `make size` 对比体积，并用 `go list -deps ./cmd/osmium-agent` 确认没有引入新的依赖。

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
E2E_LOG=1 go test -run TestShellOverSharedTunnel -v ./internal/e2e/   # 同时把日志和审计事件输出到 stderr
```

端到端测试（`internal/e2e`）需要 PATH 中有 `sshd`、`ssh`、`ssh-agent`、`ssh-add`。它会：
- 以当前用户身份，在回环地址的随机端口上启动无特权 sshd；
- 默认用进程内的假 step-ca（`internal/ca/catest`）签发证书，联调真实 step-ca 的测试见下文；
- 原生模式测试会编译 `osmium` 二进制，走完 `login` → 浏览器确认 → `ssh` 的完整流程。

测试不会改动系统里的 sshd，也不会读取开发者的 `~/.ssh`。覆盖的场景对应 [design/09-acceptance-tests.md](design/09-acceptance-tests.md)。

### 与真实 step-ca 联调

如果 PATH 中有 `step` 和 `step-ca`，`internal/e2e/stepca_test.go` 会在临时目录里 `step ca init` 一个独立 CA。它使用仓库中的 `web-user.tpl` 和 `deny-x509.tpl`，把 provisioner 时长设为 1 分钟，再用这个 CA 跑测试。如果 PATH 中没有这两个程序，相关测试会自动跳过。

```sh
nix shell nixpkgs#step-ca nixpkgs#step-cli -c go test -run StepCA -v ./internal/e2e/
```

覆盖的场景（已在 step-ca 0.30.2 和 step-cli 0.31.0 上通过）：
- `TestStepCAInterop`：
  - B01 测量有效期窗口，见下文；
  - B05 用其他 CA 校验时拒绝；
  - B06 拒绝签发主机证书、多 principal 证书和 X.509；
  - B07 申请更长有效期时不会被批准；
  - B10 一次性令牌不能重放。
- `TestStepCACertExpiry`：B02、B03、B04、B12，约 64 秒。证书过期后，已建立的 SSH 连接仍可开新 channel，新的认证会被 sshd 拒绝。
- `TestStepCAEndToEnd`：
  - Web 终端完整流程；
  - A05 跨主机拒绝；
  - 原生 `osmium ssh`。

B01 的测量结果：step-ca 默认把 `valid_after` 往前回拨 1 分钟，所以总区间是 120 秒，签发后剩余约 60 秒，见 [decisions.md](decisions.md) 的 O05。如果需要排查 CA 一侧的拒绝原因，加上 `E2E_LOG=1` 可以输出 step-ca 日志。

### 与 S3 兼容存储联调

如果 PATH 中有 `rustfs`，`internal/audit/s3_test.go` 会启动一个临时的 RustFS 服务。它检查 bucket 不存在、凭据错误和 endpoint 格式错误时会报错，并验证一个 Server 上传的审计事件，能从另一个本地目录为空的 Server 查到。如果 PATH 中没有 `rustfs`，这些测试会自动跳过。其余上传逻辑，包括封口、故障补传、去重、扫描上限和保留期，都在单元测试里用内存 Store 覆盖。

```sh
nix shell nixpkgs#rustfs -c go test -run RustFS -v ./internal/audit/
```

nixpkgs 已移除 MinIO 服务端，所以这里用 RustFS 测试。客户端使用 minio-go，与 MinIO 的兼容性由该库保证。

## 本地登录

在 server 配置里设置 `"dev_login": true` 可以不用 OIDC，然后访问 `/auth/dev-login?user=alice&group=ops`，用户的 issuer 为 `dev`。**生产环境禁止开启。**

`osmium dev pki` 用于生成本地使用的 Agent mTLS 证书。
