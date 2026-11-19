import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "shell-difftest",
    include: ["test/**/*.test.ts"],
    setupFiles: ["../../vitest.seed.ts"],
  },
});
