// Bundles the built hook (dist/*.js from tsc) with everything it imports (engine, protocol,
// valibot, @noble, re2js). Only Node built-ins stay external. rolldown is a dev dependency and
// never ships; the bundle is built in CI only (its native binary is blocked by Application
// Control on the owner's machine).
//
// Two self-contained builds:
// - dist/bundle/main.mjs: the hook process, one file. This is what ships.
// - dist/bundle-lib/index.mjs: the library surface, so CI can run the whole hook test suite
//   against bundled code (GLASSBOX_HOOK_TARGET=bundle, see vitest.config.ts).
import { builtinModules } from "node:module";
import { defineConfig } from "rolldown";

const builtins = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

const build = (name, input, dir) => ({
  input: { [name]: input },
  platform: "node",
  external: (id) => builtins.has(id),
  output: { dir, format: "esm", entryFileNames: "[name].mjs", minify: true, sourcemap: false, codeSplitting: false },
});

export default defineConfig([
  build("main", "dist/main.js", "dist/bundle"),
  build("index", "dist/index.js", "dist/bundle-lib"),
]);
