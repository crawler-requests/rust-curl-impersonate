# 官网

rust-curl-impersonate 的介绍页面：TypeScript + React + Ant Design，
配色与排版参考 Claude Code 的文档站（暖米色纸感背景、衬线标题、单一橙色强调）。

```bash
npm ci          # 安装依赖
npm run dev     # 本地开发
npm run build   # 产出 dist/
npm run preview # 预览 dist/
```

## 数据来源

`src/data/records.json` 由 `scripts/sync-library.mjs` 从仓库的
`src/fingerprint/builtin.json` 与 `tools/capture/raw/` 生成，所以页面上
显示的记录、版本与 JA4 就是库实际提供的内容。改过指纹库后重新运行：

```bash
node scripts/sync-library.mjs
```

## 部署

`main` 分支推送 `website/` 的改动时，`.github/workflows/pages.yml` 会重新
生成数据、构建并发布到 GitHub Pages。仓库设置里把 Pages 的来源选为
GitHub Actions 即可，地址是 `https://crawler-requests.github.io/rust-curl-impersonate/`；
`vite.config.ts` 的 `base` 与这个路径对应。
