#!/usr/bin/env node
// Entry point: switch on Node's compile cache, then load the hook.
//
// The cache has to be enabled before the hook's modules are loaded, and static imports load
// first, so this file loads main.js with a single dynamic import of a fixed path (the only
// dynamic import allowed in the hook; see eslint.config.js and test/banned-code.test.ts).
//
// The cache lives in ~/.glassbox/cache/node-compile: created owner-only, and protected like
// the rest of ~/.glassbox (the engine denies the agent any write there). Compiled code is
// trusted by Node, so a cache the agent could write would be a code-injection path.
// Any failure here just means no cache: the hook runs the same, only slower.
import fs from "node:fs";
import { enableCompileCache } from "node:module";
import os from "node:os";
import { parseArgs } from "./args.js";
import { compileCacheDir } from "./paths.js";

try {
  const { homeDir } = parseArgs(process.argv.slice(2), process.env, os.homedir());
  const dir = compileCacheDir(homeDir);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  enableCompileCache(dir);
} catch {
  // No cache.
}

await import("./main.js");
