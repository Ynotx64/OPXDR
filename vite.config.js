import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import cesium from "vite-plugin-cesium";
import { fileURLToPath, URL } from "node:url";

const cesiumBuildPath = fileURLToPath(new URL("./node_modules/cesium/Build/Cesium/index.js", import.meta.url));
const API_PORT = process.env.VITE_API_PORT || process.env.PORT || 8787;

export default defineConfig({
  plugins: [react(), cesium()],
  resolve: {
    alias: {
      "@cesium-built": cesiumBuildPath,
    },
  },
  publicDir: "public",
  optimizeDeps: {
    exclude: ["cesium"],
  },
  server: {
    port: 5173,
    host: "0.0.0.0",
    allowedHosts: true,
    proxy: {
      "/api": {
        target: `http://localhost:${API_PORT}`,
        changeOrigin: true,
        secure: false,
        configure: (proxy) => {
          proxy.on("error", (err) => {
            if (err.code !== "ECONNREFUSED") console.error("[proxy]", err.message);
          });
        },
      },
    },
    hmr: { overlay: false },
  },
  build: {
    outDir: "dist",
  },
});
