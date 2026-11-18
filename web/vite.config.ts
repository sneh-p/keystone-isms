import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  // The in-app help bundles docs/user-guide.md and its screenshots, which live outside web/.
  server: { proxy: { "/api": "http://127.0.0.1:8000" }, fs: { allow: [__dirname, path.resolve(__dirname, "../docs")] } },
  build: {
    outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: {
        // Long-lived vendor chunks: app releases don't invalidate the cached libraries.
        manualChunks: {
          react: ["react", "react-dom", "react-router"],
          ui: ["@radix-ui/react-checkbox", "@radix-ui/react-dialog", "@radix-ui/react-dropdown-menu", "@radix-ui/react-popover", "@radix-ui/react-progress", "@radix-ui/react-select", "@radix-ui/react-switch", "@radix-ui/react-tabs", "@radix-ui/react-tooltip", "cmdk", "sonner"],
          query: ["@tanstack/react-query"],
        },
      },
    },
  },
  test: { environment: "node" },
});
