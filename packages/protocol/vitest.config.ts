import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "protocol",
    include: ["test/**/*.test.ts"],
    setupFiles: ["../../vitest.seed.ts"],
  },
});
