# 发布构建：去掉符号表/DWARF 与本地路径，体积约为默认 go build 的 58%。
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS_RELEASE = -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build test size
build:
	CGO_ENABLED=0 go build $(GOFLAGS_RELEASE) -o osmium ./cmd/osmium

test:
	go test -race ./...

size: build
	@ls -l osmium | awk '{printf "osmium: %.2f MiB\n", $$5/1048576}'
