import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
    plugins: [react()],
    build: {
        outDir: "../build/frontend-resources/static/",
        emptyOutDir: true,
    },
    server: {
        proxy: {
            "/api": "http://localhost:8080",
        },
    },
    resolve: {
        alias: {
            "@": path.resolve(__dirname, "./src"),
        },
    },
});
