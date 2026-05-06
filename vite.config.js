import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "100.86.115.94",
    allowedHosts: true,
    proxy: {
      "/api": {
        target: "http://100.86.115.94:8787",
        changeOrigin: true,
      },
    },
  },
});
