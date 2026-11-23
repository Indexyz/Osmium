# Changesets

本仓库使用 [Changesets](https://changesets.dev/) 追踪变更并自动驱动版本发布（Git Tag、GitHub Release、GHCR 镜像与跨平台二进制产物）。

## 日常提交流程

1. 开发完成需要写入变更日志的功能或修复后，在仓库根目录运行：

   ```sh
   npm run changeset
   ```

2. 按提示选择版本级别（`patch` / `minor` / `major`）并填写变更说明，把生成的 `.changeset/*.md` 文件随代码一起提交到 PR。
3. PR 合并到 `main` 后，GitHub Actions（`changesets/action`）会自动创建或更新 **Version Packages** PR，汇总更新 `package.json` 版本号与 `CHANGELOG.md`。
4. 合并 **Version Packages** PR 后，工作流会自动：
   - 创建并推送 `vX.Y.Z` Git Tag 与 GitHub Release；
   - 构建并推送多架构容器镜像到 `ghcr.io/indexyz/osmium` 与 `ghcr.io/indexyz/osmium-agent`；
   - 构建并上传多平台 `osmium` 与 `osmium-agent` 二进制包及校验和到 GitHub Release。
