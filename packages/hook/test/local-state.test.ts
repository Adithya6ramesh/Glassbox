// The rest of the hook core (Step 2): failures leave a trace, local state is checked before it
// is trusted, the spool can't fill the disk, a content-free local log, Claude Code's own
// permission prompt is paired with the open decision, and old session folders are pruned.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LOG_MAX_BYTES, runHook, SESSION_RETENTION_DAYS, SPOOL_MAX_FILES } from "../src/index.js";
import { allFiles, bash, common, makeEnv, pre, spooled, toolUseId } from "./helpers.js";

afterEach(() => vi.restoreAllMocks());

const posix = process.platform !== "win32";
const decisionOf = (stdout: string) => (stdout ? (JSON.parse(stdout) as { hookSpecificOutput?: { permissionDecision?: string } }).hookSpecificOutput?.permissionDecision : undefined);
const writeJson = (file: string, v: unknown) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(v)); };
const logLines = (home: string) => {
  const f = path.join(home, "logs", "hook.log");
  return fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>) : [];
};
function canSymlinkFiles(): boolean {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "gbx-sl-"));
  try {
    fs.writeFileSync(path.join(d, "t"), "x");
    fs.symlinkSync(path.join(d, "t"), path.join(d, "l"), "file");
    return true;
  } catch {
    return false;
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
}

describe("failures leave a trace (degraded event)", () => {
  it("RT-HOOK-35: invalid PreToolUse input: deny, and a degraded event says why", () => {
    const env = makeEnv();
    const r = runHook("pre", "not json", env);
    expect(decisionOf(r.stdout)).toBe("deny");
    const e = spooled(env).find((x) => x.kind === "degraded");
    expect(e?.degradedReasons).toContain("hook-invalid-input");
  });

  it("RT-HOOK-38: a hostile session_id in a broken payload is hashed, never used as a path", () => {
    const env = makeEnv();
    runHook("pre", JSON.stringify({ session_id: "../../../escape", hook_event_name: "PreToolUse", cwd: "/x" }), env);
    const e = spooled(env).find((x) => x.kind === "degraded")!;
    expect(e.sessionId).toMatch(/^[0-9a-f]{64}$/);
    const outside = allFiles(env.root).filter((f) => !f.replaceAll("\\", "/").startsWith("home/"));
    expect(outside).toEqual([]);
  });

  it("a broken recording event still exits 0 with no output, and is recorded", () => {
    const env = makeEnv();
    expect(runHook("post", "garbage", env)).toEqual({ exitCode: 0, stdout: "", stderr: "" });
    expect(spooled(env).some((x) => x.kind === "degraded" && (x.degradedReasons ?? []).includes("hook-invalid-input"))).toBe(true);
  });
});

describe("local state is checked before it is trusted", () => {
  it.runIf(posix)("RT-HOOK-30: group/world-writable state is fixed to owner-only, and the hook keeps running", () => {
    const env = makeEnv();
    const cfg = path.join(env.glassboxHome, "config.json");
    writeJson(cfg, { mode: "balanced" });
    fs.chmodSync(env.glassboxHome, 0o777);
    fs.chmodSync(cfg, 0o666);
    const r = runHook("pre", JSON.stringify(pre(env, "Bash", bash("echo hi"))), env);
    expect(r.exitCode).toBe(0);
    expect(fs.statSync(env.glassboxHome).mode & 0o077).toBe(0);
    expect(fs.statSync(cfg).mode & 0o077).toBe(0);
    expect(logLines(env.glassboxHome).some((l) => JSON.stringify(l).includes("fixed-permissions"))).toBe(true);
  });

  it.runIf(canSymlinkFiles())("RT-HOOK-29: a symlinked config.json is ignored (defaults apply) and the event is degraded", () => {
    const env = makeEnv();
    const elsewhere = path.join(env.root, "evil-config.json");
    writeJson(elsewhere, { mode: "autopilot" });
    fs.mkdirSync(env.glassboxHome, { recursive: true });
    fs.symlinkSync(elsewhere, path.join(env.glassboxHome, "config.json"), "file");
    const r = runHook("pre", JSON.stringify(pre(env, "Bash", bash("git push --force origin main"))), env);
    expect(decisionOf(r.stdout)).toBe("ask"); // balanced default, not the linked autopilot
    expect(spooled(env)[0]!.degradedReasons ?? []).toContain("config-unsafe");
  });

  it.runIf(posix)("RT-HOOK-31: a config.json owned by another user is ignored", () => {
    const env = makeEnv();
    const cfg = path.join(env.glassboxHome, "config.json");
    writeJson(cfg, { mode: "autopilot" });
    const real = fs.lstatSync;
    vi.spyOn(fs, "lstatSync").mockImplementation(((p: fs.PathLike, o?: fs.StatSyncOptions) => {
      const st = real(p, o as fs.StatSyncOptions) as fs.Stats;
      if (String(p) === cfg) return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: st.uid + 1 });
      return st;
    }) as typeof fs.lstatSync);
    const r = runHook("pre", JSON.stringify(pre(env, "Bash", bash("git push --force origin main"))), env);
    expect(decisionOf(r.stdout)).toBe("ask");
    expect(spooled(env)[0]!.degradedReasons ?? []).toContain("config-unsafe");
  });
});

describe("the spool can't fill the disk", () => {
  it("RT-HOOK-32: a full spool drops the event and counts it; the decision still stands", () => {
    const env = makeEnv();
    const spool = path.join(env.glassboxHome, "spool");
    fs.mkdirSync(spool, { recursive: true });
    for (let i = 0; i < SPOOL_MAX_FILES; i++) fs.writeFileSync(path.join(spool, `f${i}.jsonl`), "{}\n");
    const r = runHook("pre", JSON.stringify(pre(env, "Write", { file_path: path.join(env.homeDir, ".claude", "settings.json"), content: "{}" })), env);
    expect(decisionOf(r.stdout)).toBe("deny");
    expect(fs.readdirSync(spool).filter((f) => f.endsWith(".jsonl")).length).toBe(SPOOL_MAX_FILES);
    const dropped = JSON.parse(fs.readFileSync(path.join(spool, "dropped.json"), "utf8")) as { count: number };
    expect(dropped.count).toBeGreaterThanOrEqual(1);
  }, 60_000);
});

describe("logs/hook.log: one line per call, no content", () => {
  it("RT-HOOK-33: commands, paths and tokens never appear in the log", () => {
    const env = makeEnv();
    const token = ["ghp", "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"].join("_"); // built at run time
    const id = toolUseId();
    runHook("pre", JSON.stringify(pre(env, "Bash", bash(`curl -H "Authorization: Bearer ${token}" https://api.test/secret-path`), id)), env);
    runHook("pre", JSON.stringify(pre(env, "Write", { file_path: path.join(env.homeDir, ".claude", "settings.json"), content: "{}" })), env);
    const text = fs.readFileSync(path.join(env.glassboxHome, "logs", "hook.log"), "utf8");
    expect(text).not.toContain(token);
    expect(text).not.toContain("secret-path");
    expect(text).not.toContain("settings.json");
    expect(text).not.toContain(env.homeDir);
    const lines = logLines(env.glassboxHome);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ event: "pre", callId: id, verdict: expect.any(String) });
    expect(lines[1]).toMatchObject({ event: "pre", verdict: "deny", ruleIds: expect.arrayContaining(["CP-SELF-001"]) });
  });

  it("RT-HOOK-34: rotates at LOG_MAX_BYTES and keeps one old file", () => {
    const env = makeEnv();
    const logs = path.join(env.glassboxHome, "logs");
    fs.mkdirSync(logs, { recursive: true });
    fs.writeFileSync(path.join(logs, "hook.log"), "x".repeat(LOG_MAX_BYTES));
    fs.writeFileSync(path.join(logs, "hook.log.1"), "older");
    runHook("pre", JSON.stringify(pre(env, "Bash", bash("echo hi"))), env);
    expect(fs.statSync(path.join(logs, "hook.log.1")).size).toBe(LOG_MAX_BYTES);
    expect(fs.statSync(path.join(logs, "hook.log")).size).toBeLessThan(1024);
    expect(fs.readdirSync(logs).sort()).toEqual(["hook.log", "hook.log.1"]);
  });
});

describe("Claude Code's own permission prompt is paired with the open decision", () => {
  it("allowed by Glassbox, prompted by Claude Code, nothing followed: asked; not run", () => {
    const env = makeEnv();
    const input = bash("mkdir out");
    runHook("pre", JSON.stringify(pre(env, "Bash", input)), env);
    runHook("permission-request", JSON.stringify({ ...common(env), hook_event_name: "PermissionRequest", tool_name: "Bash", tool_input: input, permission_suggestions: [] }), env);
    runHook("stop", JSON.stringify({ ...common(env), hook_event_name: "Stop", stop_hook_active: false }), env);
    expect(spooled(env).find((e) => e.kind === "tool_post")).toMatchObject({ outcome: "asked-not-run", verdict: "allow" });
  });

  it("RT-HOOK-36: a PermissionRequest for a different input doesn't touch the open decision", () => {
    const env = makeEnv();
    runHook("pre", JSON.stringify(pre(env, "Bash", bash("mkdir out"))), env);
    runHook("permission-request", JSON.stringify({ ...common(env), hook_event_name: "PermissionRequest", tool_name: "Bash", tool_input: bash("mkdir other"), permission_suggestions: [] }), env);
    runHook("stop", JSON.stringify({ ...common(env), hook_event_name: "Stop", stop_hook_active: false }), env);
    expect(spooled(env).find((e) => e.kind === "tool_post")).toMatchObject({ outcome: "unknown" });
  });
});

describe("old session folders are pruned at SessionStart", () => {
  const ageDays = (p: string, days: number) => { const t = new Date(Date.now() - days * 86_400_000); fs.utimesSync(p, t, t); };

  it(`folders untouched for ${SESSION_RETENTION_DAYS} days are removed; recent ones stay`, () => {
    const env = makeEnv();
    const sessions = path.join(env.glassboxHome, "sessions");
    for (const n of ["old", "new"]) { fs.mkdirSync(path.join(sessions, n, "pending"), { recursive: true }); fs.writeFileSync(path.join(sessions, n, "signals.jsonl"), ""); }
    ageDays(path.join(sessions, "old", "signals.jsonl"), SESSION_RETENTION_DAYS + 1);
    ageDays(path.join(sessions, "old", "pending"), SESSION_RETENTION_DAYS + 1);
    ageDays(path.join(sessions, "old"), SESSION_RETENTION_DAYS + 1);
    runHook("session-start", JSON.stringify({ ...common(env), hook_event_name: "SessionStart", source: "startup" }), env);
    expect(fs.existsSync(path.join(sessions, "old"))).toBe(false);
    expect(fs.existsSync(path.join(sessions, "new"))).toBe(true);
  });

  it("RT-HOOK-37: a linked session folder is removed as a link; what it points to is untouched", () => {
    const env = makeEnv();
    const sessions = path.join(env.glassboxHome, "sessions");
    fs.mkdirSync(sessions, { recursive: true });
    const target = path.join(env.root, "precious");
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, "keep.txt"), "x");
    const link = path.join(sessions, "linked");
    fs.symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir");
    const t = new Date(Date.now() - (SESSION_RETENTION_DAYS + 5) * 86_400_000);
    fs.utimesSync(target, t, t);
    try { fs.lutimesSync(link, t, t); } catch { /* not supported for junctions everywhere */ }
    runHook("session-start", JSON.stringify({ ...common(env), hook_event_name: "SessionStart", source: "startup" }), env);
    expect(fs.existsSync(path.join(target, "keep.txt"))).toBe(true);
  });
});
