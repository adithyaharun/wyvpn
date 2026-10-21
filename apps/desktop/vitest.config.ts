import { sveltekit } from "@sveltejs/kit/vite";
import { svelteTesting } from "@testing-library/svelte/vite";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [sveltekit(), svelteTesting()],
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
    setupFiles: ["./src/test-setup.ts"],
    css: { include: [/(ProfileList|SettingsSheet|StatusPanel)\.svelte/, /\/src\/app\.css$/] },
  },
});
