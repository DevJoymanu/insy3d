// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import fs from "fs";
import path from "path";

export default defineConfig({
  plugins: [react()],
  server: {
    https: {
      key: fs.readFileSync(path.resolve(".cert/key.pem")),
      cert: fs.readFileSync(path.resolve(".cert/cert.pem")),
    },
    host: "localhost",
    port: 5173,
  },
});