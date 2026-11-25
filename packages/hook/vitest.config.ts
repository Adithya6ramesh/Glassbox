import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// GLASSBOX_HOOK_TARGET=bundle runs the whole suite against the built bundle (CI and the release
// workflow): every test's import of ../src/index.js resolves to dist/bundle-lib/index.mjs, and
// main.test.ts starts dist/bundle/main.mjs. Build it first: pnpm --filter @glassbox-ai/hook run bundle.
const bundle = process.env["GLASSBOX_HOOK_TARGET"] === "bundle";

export default defineConfig({
  resolve: {
    alias: bundle ? [{ find: /^\.\.\/src\/index\.js$/, replacement: fileURLToPath(new URL("./dist/bundle-lib/index.mjs", import.meta.url)) }] : [],
  },
  test: {
    name: bundle ? "hook (bundle)" : "hook",
    include: ["test/**/*.test.ts"],
    setupFiles: ["../../vitest.seed.ts"],
    // main.test.ts starts real hook processes.
    testTimeout: 20_000,
  },
});
