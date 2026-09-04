import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// Proxy API + WebSocket calls to the FastAPI backend during development,
// so the frontend can use same-origin relative URLs like "/api/scans".
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
