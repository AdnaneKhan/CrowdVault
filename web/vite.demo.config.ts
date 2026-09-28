// Self-contained demo build: one HTML file, running against the pretend vault.
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig({
  plugins: [react(), viteSingleFile()],
  define: { "import.meta.env.VITE_DEFAULT_DEMO": JSON.stringify("1") },
  build: { outDir: "dist-demo" },
});
