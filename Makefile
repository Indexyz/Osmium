# 发布构建：去掉符号表/DWARF 与本地路径，体积约为默认 go build 的 58%。
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS_RELEASE = -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build agent test size
build:
	CGO_ENABLED=0 go build $(GOFLAGS_RELEASE) -o osmium ./cmd/osmium

# 目标主机（边缘设备）上的独立 Agent：不含 Server、CLI、cobra。
# 交叉编译示例：make agent GOOS=linux GOARCH=arm64
agent:
	CGO_ENABLED=0 go build $(GOFLAGS_RELEASE) -o osmium-agent ./cmd/osmium-agent

test:
	go test -race ./...

size: build agent
	@ls -l osmium osmium-agent | awk '{printf "%-14s %.2f MiB\n", $$9, $$5/1048576}'
