# Changelog

All notable changes to Osmium are tracked with [Changesets](https://changesets.dev/).

## 0.1.0

### Initial Release

- Web SSH 访问系统：OIDC 登录、策略驱动授权、step-ca 短期 SSH 用户证书签发、Host Key Pinning 与结构化审计（本地 JSONL 分段 + S3 兼容存储归档）。
- 主机反向隧道 Agent：mTLS 控制通道 + `smux v2` 常驻数据通道，提供面向边缘设备的独立轻量二进制 `osmium-agent`。
- 原生 OpenSSH 客户端接入（`osmium login` / `osmium hosts` / `osmium ssh`）与限时 `ssh-agent` 集成。
- Web 终端迁移至 React + TypeScript + `ghostty-web`（WASM），本地打包嵌入二进制，移除外部 CDN 依赖。
- 安全与稳定性护栏：策略级 `disabled_users`、管理员 CLI 令牌与用户集中吊销 API、未认证 pending stream 与 CA 并发签发限流、会话空闲超时、可选 `source-address` loopback 证书模板及 `/healthz` 健康检查。
