import react from "@vitejs/plugin-react";
import tailwindcss from "tailwindcss";
import { defineConfig } from "vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  publicDir: "./static",
  base: "./",
  css: {
    postcss: {
      plugins: [tailwindcss],
    },
  },
  server: {
    host: 'localhost',
    port: 3002, // Changed to 3002 to avoid conflicts
  },
});