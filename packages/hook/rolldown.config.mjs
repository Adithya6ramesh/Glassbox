// Bundles the built hook (dist/*.js from tsc) with everything it imports (engine, protocol,
// valibot, @noble, re2js) into dist/bundle/: the small launcher plus one chunk for the rest.
// Two files on purpose: the launcher must enable Node's compile cache before the big chunk is
// loaded. Only Node built-ins stay external. rolldown is a dev dependency: never shipped.
import { builtinModules } from "node:module";
import { defineConfig } from "rolldown";

const builtins = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

export default defineConfig({
  input: { launch: "dist/launch.js" },
  platform: "node",
  external: (id) => builtins.has(id),
  output: {
    dir: "dist/bundle",
    format: "esm",
    entryFileNames: "[name].mjs",
    chunkFileNames: "hook-[hash].mjs",
    minify: true,
    sourcemap: false,
    // Keep the dynamic import as its own chunk (see launch.ts).
    codeSplitting: true,
  },
});
