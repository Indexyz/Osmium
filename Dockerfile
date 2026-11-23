# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM node:22-alpine AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS go-builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY web/web.go web/web.go
COPY --from=web-builder /src/web/dist web/dist
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/osmium ./cmd/osmium
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/osmium-agent ./cmd/osmium-agent

FROM gcr.io/distroless/static-debian12:nonroot AS agent
LABEL org.opencontainers.image.title="osmium-agent" \
      org.opencontainers.image.description="Standalone host reverse-tunnel Agent for Osmium" \
      org.opencontainers.image.source="https://github.com/Indexyz/Osmium"
COPY --from=go-builder /out/osmium-agent /usr/local/bin/osmium-agent
ENTRYPOINT ["/usr/local/bin/osmium-agent"]
CMD ["-c", "/etc/osmium-agent/agent.json"]

FROM gcr.io/distroless/static-debian12:nonroot AS server
LABEL org.opencontainers.image.title="osmium" \
      org.opencontainers.image.description="Osmium Web & Native SSH access server" \
      org.opencontainers.image.source="https://github.com/Indexyz/Osmium"
COPY --from=go-builder /out/osmium /usr/local/bin/osmium
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/osmium"]
CMD ["server", "-c", "/etc/osmium/server.json"]
