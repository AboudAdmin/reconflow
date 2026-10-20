import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// One self-contained HTML file (no network, works from file://) that the Go
// binary embeds and fills with the report JSON.
export default defineConfig({ plugins: [react(), viteSingleFile()], build: { outDir: "dist", emptyOutDir: true } });
