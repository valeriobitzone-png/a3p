import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

const root = dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": resolve(root, "src") },
  },
  build: {
    rollupOptions: {
      input: {
        main: resolve(root, "index.html"),
        verify: resolve(root, "verify/index.html"),
        results: resolve(root, "results/index.html"),
      },
    },
  },
})
