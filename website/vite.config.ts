import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `base` is the repository path, because the site is published from GitHub
// Pages at https://<owner>.github.io/<repo>/. A custom domain would need this
// changed, nothing else.
export default defineConfig({
  base: "/rust-curl-impersonate/",
  plugins: [react()],
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
