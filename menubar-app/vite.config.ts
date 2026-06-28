import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

const config = defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: "es2021",
    minify: "esbuild",
    sourcemap: false,
  },
});

export default config;
