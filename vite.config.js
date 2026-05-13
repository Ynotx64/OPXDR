import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Backend (Express) runs on PORT from .env (default 5174)
// Frontend (Vite dev) runs on 5173
// geo.html is served as a static file from public/ — no transformation

const API_PORT = process.env.VITE_API_PORT || process.env.PORT || 5174;

export default defineConfig({
  plugins: [react()],
  publicDir: "public",
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
