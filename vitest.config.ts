import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: ["packages/*"],
    include: ["test/**/*.test.ts"],
  },
});
