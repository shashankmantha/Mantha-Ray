import { defineConfig } from "vite";

export default defineConfig({
  base: "./",

  build: {
    outDir: "../src/static_triage/web_dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});