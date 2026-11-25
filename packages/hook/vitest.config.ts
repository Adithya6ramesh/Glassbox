import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "hook",
    include: ["test/**/*.test.ts"],
    setupFiles: ["../../vitest.seed.ts"],
    // main.test.ts starts real hook processes.
    testTimeout: 20_000,
  },
});
