// Runs the built hook as a real process (dist/main.js), the way Claude Code does.
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { compileCacheDir, parseArgs } from "../src/index.js";
import { bash, makeEnv, pre } from "./helpers.js";

const MAIN = fileURLToPath(new URL("../dist/launch.js", import.meta.url));

function runMain(args: string[], stdin: string | null, envVars: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string; ms: number }> {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const p = spawn(process.execPath, [MAIN, ...args], { env: { ...process.env, ...envVars }, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    p.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    p.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    p.on("close", (code) => resolve({ code, stdout, stderr, ms: performance.now() - t0 }));
    // Over the cap the hook stops reading on purpose; the rest of our write then gets EPIPE.
    p.stdin.on("error", () => {});
    if (stdin !== null) p.stdin.end(stdin); // null: leave stdin open (a stalled writer)
  });
}

describe("main (real process)", () => {
  it("is built", () => {
    expect(fs.existsSync(MAIN)).toBe(true);
  });

  it("deny: JSON on stdout, exit 0", async () => {
    const env = makeEnv();
    const payload = pre(env, "Write", { file_path: path.join(env.homeDir, ".claude", "settings.json"), content: "{}" });
    const r = await runMain(["pre", "--home", env.homeDir], JSON.stringify(payload));
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("allow: no output, exit 0", async () => {
    const env = makeEnv();
    const r = await runMain(["pre", "--home", env.homeDir], JSON.stringify(pre(env, "Bash", bash("echo hi"))));
    expect(r).toMatchObject({ code: 0, stdout: "" });
  });

  it("RT-HOOK-17: a stalled stdin hits the internal deadline and fails closed, well before Claude Code's 5 s timeout", async () => {
    const env = makeEnv();
    const r = await runMain(["pre", "--home", env.homeDir], null);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r.ms).toBeLessThan(3000);
  });

  it("RT-HOOK-18: stdin over the 2 MiB cap fails closed without reading it all", async () => {
    const env = makeEnv();
    const big = JSON.stringify(pre(env, "Bash", bash("echo " + "x".repeat(3 * 1024 * 1024))));
    const r = await runMain(["pre", "--home", env.homeDir], big);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("RT-HOOK-19: an unknown event argument never blocks (exit 0, no output)", async () => {
    const env = makeEnv();
    const r = await runMain(["no-such-event", "--home", env.homeDir], "{}");
    expect(r).toMatchObject({ code: 0, stdout: "" });
  });

  it("RT-HOOK-20: the state folder can't be redirected through the environment", () => {
    // A repository's settings can set environment variables for Claude Code and its hooks.
    // Only the hook's own command line (written by the installer) may choose the folder; no
    // GLASSBOX_* variable is read. (The default comes from os.homedir(), which follows HOME /
    // USERPROFILE exactly as Claude Code's own ~/.claude does.)
    const a = parseArgs(["pre"], { GLASSBOX_HOME: "/tmp/evil", GLASSBOX_DIR: "/tmp/evil" }, "/home/real");
    expect(a.homeDir).toBe("/home/real");
    expect(parseArgs(["pre", "--home", "/x"], {}, "/home/real").homeDir).toBe("/x");
  });

  it("compile cache: a run creates ~/.glassbox/cache/node-compile, owner-only on POSIX", async () => {
    const env = makeEnv();
    await runMain(["pre", "--home", env.homeDir], JSON.stringify(pre(env, "Bash", bash("echo hi"))));
    const dir = compileCacheDir(env.homeDir);
    expect(fs.existsSync(dir)).toBe(true);
    expect(fs.readdirSync(dir, { recursive: true }).length).toBeGreaterThan(0);
    if (process.platform !== "win32") expect(fs.statSync(dir).mode & 0o077).toBe(0);
  });

  it("RT-HOOK-25: the agent can't write into the compile cache (code injection path)", async () => {
    const env = makeEnv();
    const target = path.join(compileCacheDir(env.homeDir), "evil.bin");
    for (const payload of [
      pre(env, "Write", { file_path: target, content: "x" }),
      pre(env, "Bash", bash(`cp /tmp/x '${target}'`)),
      pre(env, "PowerShell", { command: `Set-Content -Path '${target}' -Value x` }),
    ]) {
      const r = await runMain(["pre", "--home", env.homeDir], JSON.stringify(payload));
      expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
    }
  });

  it("parseArgs: --home needs a value; an event is required", () => {
    expect(parseArgs(["pre", "--home"], {}, "/h").homeDir).toBe("/h");
    expect(parseArgs([], {}, "/h").event).toBeNull();
  });
});
