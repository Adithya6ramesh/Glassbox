#!/usr/bin/env node
// Process wrapper around runHook: deadline first, then a capped stdin read, then the reply.
import fs from "node:fs";
import os from "node:os";
import { parseArgs } from "./args.js";
import { glassboxHomeOf } from "./paths.js";
import { failReply } from "./failrules.js";
import { blockingReasonOf, writeReply, type Reply } from "./reply.js";
import { recordFailure, runHook, writeCallLog } from "./run.js";
import type { HookEnv } from "./context.js";

const STARTED_AT_MS = performance.now();
const MAX_STDIN = 2 * 1024 * 1024;

const { event, homeDir } = parseArgs(process.argv.slice(2), process.env, os.homedir());
/**
 * Wall clock since process start, per event: room for start-up plus the engine's time limit
 * (750 ms PreToolUse, 1,500 ms otherwise; see HARD_STOP_MS), and well under the 5 s Claude Code
 * timeout in the registration.
 */
const DEADLINE_MS = event === "pre" ? 1200 : 2000;
const platform = process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux";

const env: HookEnv = {
  homeDir,
  glassboxHome: glassboxHomeOf(homeDir),
  platform,
  pluginRoot: process.env["CLAUDE_PLUGIN_ROOT"] || undefined,
  claudeConfigDir: process.env["CLAUDE_CONFIG_DIR"] || undefined,
  startedAtMs: STARTED_AT_MS,
};

let finished = false;
/** A failure outside runHook (deadline, stdin cap, stdin error): reply by the fail rule and record it. */
function fail(cause: "hook-timeout" | "hook-stdin-too-large" | "hook-stdin-error", why: "timeout" | "invalid input"): void {
  if (finished) return;
  const reply = failReply(event, undefined, why);
  recordFailure(env, event ?? "", cause, null, reply);
  writeCallLog(env, STARTED_AT_MS);
  finish(reply);
}
function finish(reply: Reply): void {
  if (finished) return;
  finished = true;
  const code = writeReply(reply, { stdout: (s) => fs.writeSync(1, s), stderr: (s) => fs.writeSync(2, s) }, blockingReasonOf(reply));
  process.exit(code);
}

// Armed before stdin is read, so a stalled writer can't hold the call.
setTimeout(() => fail("hook-timeout", "timeout"), Math.max(0, DEADLINE_MS - performance.now())).unref();

const chunks: Buffer[] = [];
let size = 0;
process.stdin.on("data", (c: Buffer) => {
  size += c.length;
  if (size > MAX_STDIN) {
    process.stdin.destroy();
    fail("hook-stdin-too-large", "invalid input");
    return;
  }
  chunks.push(c);
});
process.stdin.on("error", () => fail("hook-stdin-error", "invalid input"));
process.stdin.on("end", () => {
  if (finished) return;
  try {
    finish(runHook(event ?? "", Buffer.concat(chunks).toString("utf8"), env));
  } catch {
    finish(failReply(event, undefined, "internal error"));
  }
});
