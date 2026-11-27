// ConfigChange handler, settings snapshot, start-up and per-call drift checks, strict mode
// (Phase 2 Step 2). Observed live on Claude Code 2.1.332 (2026-11-27): ConfigChange carries no
// file content; a block keeps the session's previous settings but leaves the file on disk; and
// settings written while no session runs fire no event and are loaded at the next start.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { confirmSettings, onConfigChange, runHook, type HookEnv } from "../src/index.js";
import { bash, common, makeEnv, pre, SESSION, spooled } from "./helpers.js";

type Env = HookEnv & { root: string; project: string };
/** No managed-settings paths: tests never read the machine's real managed settings. */
const envOf = (): Env => makeEnv({ managedSettingsPaths: [] });
const userFile = (env: Env) => path.join(env.homeDir, ".claude", "settings.json");
const projectFile = (env: Env) => path.join(env.project, ".claude", "settings.json");
const localFile = (env: Env) => path.join(env.project, ".claude", "settings.local.json");
const writeJson = (file: string, v: unknown) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(v)); };

const sessionStart = (env: Env, session = SESSION) =>
  runHook("session-start", JSON.stringify({ ...common(env, { session_id: session }), hook_event_name: "SessionStart", source: "startup", model: "x" }), env);
const configChange = (env: Env, source: string, file?: string, session = SESSION) =>
  runHook("config-change", JSON.stringify({ ...common(env, { session_id: session }), hook_event_name: "ConfigChange", source, ...(file ? { file_path: file } : {}) }), env);
const decisionOf = (stdout: string) => (stdout ? (JSON.parse(stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } }).hookSpecificOutput : undefined);
const writeCall = (env: Env, session = SESSION) =>
  runHook("pre", JSON.stringify({ ...pre(env, "Write", { file_path: path.join(env.project, "a.txt"), content: "x" }), session_id: session }), env);
const readCall = (env: Env) => runHook("pre", JSON.stringify(pre(env, "Read", { file_path: path.join(env.project, "a.txt") })), env);
const settingsEvents = (env: Env) => spooled(env).filter((e) => e.kind === "settings_change");
const blockReply = (stdout: string) => (stdout ? (JSON.parse(stdout) as { decision?: string; reason?: string }) : {});

describe("ConfigChange", () => {
  it("an ordinary change is allowed, recorded with its key names, and approved", () => {
    const env = envOf();
    sessionStart(env);
    writeJson(localFile(env), { env: { GBX_PROBE: "allowed-change" } });
    const r = configChange(env, "local_settings", localFile(env));
    expect(r).toEqual({ exitCode: 0, stdout: "", stderr: "" });
    const e = settingsEvents(env).at(-1)!;
    expect(e.summary?.settings).toMatchObject({ scope: "local", level: "ordinary", action: "allowed", via: "config-change", changedKeys: ["env.GBX_PROBE"] });
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBeUndefined();
  });

  it("RT-HOOK-46: a dangerous change is allowed but switches to strict mode: non-read tools ask until confirmed", () => {
    const env = envOf();
    sessionStart(env);
    writeJson(localFile(env), { env: { NODE_OPTIONS: "--require /tmp/x.js" } });
    expect(configChange(env, "local_settings", localFile(env)).stdout).toBe("");
    const w = decisionOf(writeCall(env).stdout);
    expect(w?.permissionDecision).toBe("ask");
    expect(w?.permissionDecisionReason).toMatch(/glassbox confirm-settings/);
    expect(w?.permissionDecisionReason).toMatch(/env\.NODE_OPTIONS/);
    expect(decisionOf(readCall(env).stdout)?.permissionDecision).toBeUndefined(); // read-only tools still run
    // A call the engine denies stays denied (strict mode never loosens).
    expect(decisionOf(runHook("pre", JSON.stringify(pre(env, "Bash", bash("rm -rf ~"))), env).stdout)?.permissionDecision).toBe("deny");
    expect(settingsEvents(env).at(-1)?.summary?.settings).toMatchObject({ level: "dangerous", action: "strict" });

    confirmSettings(env, env.project);
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBeUndefined();
  });

  it("RT-HOOK-47: disableAllHooks is blocked (JSON reply), recorded, and the blocked file is reported at the next start", () => {
    const env = envOf();
    sessionStart(env);
    writeJson(projectFile(env), { disableAllHooks: true });
    const r = configChange(env, "project_settings", projectFile(env));
    expect(r.exitCode).toBe(0);
    expect(blockReply(r.stdout)).toMatchObject({ decision: "block" });
    expect(blockReply(r.stdout).reason).toMatch(/Glassbox/);
    expect(settingsEvents(env).at(-1)?.summary?.settings).toMatchObject({ action: "blocked", reasons: ["disable-all-hooks"] });
    // This session keeps its approved settings (the block worked), so it isn't strict.
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBeUndefined();

    // The blocked content is still on disk; the next session loads it.
    const next = "00000000-0000-4000-8000-0000000000cc";
    sessionStart(env, next);
    const w = decisionOf(writeCall(env, next).stdout);
    expect(w?.permissionDecision).toBe("ask");
    expect(w?.permissionDecisionReason).toMatch(/blocked earlier/);
    expect(settingsEvents(env).at(-1)?.summary?.settings).toMatchObject({ via: "session-start", blockedEarlier: true });
  });

  it("RT-HOOK-48: the file changed while it was being checked → blocked (time-of-check/time-of-use)", () => {
    const env = envOf();
    sessionStart(env);
    let n = 0;
    const reads = [Buffer.from('{"model":"opus"}'), Buffer.from('{"model":"opus","env":{"NODE_OPTIONS":"--require /tmp/x.js"}}')];
    const r = onConfigChange(env, { sessionId: SESSION, cwd: env.project, source: "local_settings", filePath: localFile(env) }, () => reads[Math.min(n++, 1)]!);
    expect(n).toBeGreaterThanOrEqual(2);
    expect(r.block).toMatch(/changed while Glassbox was checking/);
  });

  it("RT-HOOK-49: a burst of changes to one file is blocked, even when each change is ordinary", () => {
    const env = envOf();
    sessionStart(env);
    const replies: string[] = [];
    for (let i = 0; i < 5; i++) {
      writeJson(localFile(env), { model: `m${i}` });
      replies.push(configChange(env, "local_settings", localFile(env)).stdout);
    }
    expect(replies.slice(0, 3).every((s) => s === "")).toBe(true);
    expect(blockReply(replies[3]!)).toMatchObject({ decision: "block" });
    expect(blockReply(replies[3]!).reason).toMatch(/quick succession/);
  });

  it("RT-HOOK-50: a file that can't be read as settings is blocked (fail closed)", () => {
    const env = envOf();
    sessionStart(env);
    fs.mkdirSync(path.dirname(localFile(env)), { recursive: true });
    fs.writeFileSync(localFile(env), '{"env":{"A":1},}');
    expect(blockReply(configChange(env, "local_settings", localFile(env)).stdout)).toMatchObject({ decision: "block" });
    fs.writeFileSync(localFile(env), Buffer.alloc(2 * 1024 * 1024, 0x20));
    expect(blockReply(configChange(env, "local_settings", localFile(env)).stdout)).toMatchObject({ decision: "block" });
  });

  it("RT-HOOK-51: a file_path outside the known settings files is judged as the file for its source", () => {
    const env = envOf();
    sessionStart(env);
    const decoy = path.join(env.project, "decoy.json");
    writeJson(decoy, { theme: "dark" });
    writeJson(localFile(env), { disableAllHooks: true });
    // Claude Code's file for local_settings is the project's settings.local.json, whatever file_path says.
    expect(blockReply(configChange(env, "local_settings", decoy).stdout)).toMatchObject({ decision: "block" });
  });

  it("RT-HOOK-60: a ConfigChange payload the hook can't read is blocked (fail closed), and recorded", () => {
    const env = envOf();
    for (const text of ["not json", "{}", JSON.stringify({ hook_event_name: "ConfigChange" })]) {
      const r = runHook("config-change", text, env);
      expect(blockReply(r.stdout), text).toMatchObject({ decision: "block" });
    }
    expect(spooled(env).some((e) => e.kind === "degraded" && (e.degradedReasons ?? []).includes("hook-invalid-input"))).toBe(true);
  });

  it("policy settings can't be blocked: recorded only", () => {
    const env = envOf();
    sessionStart(env);
    const r = configChange(env, "policy_settings");
    expect(r.stdout).toBe("");
  });

  it("the sanitized live capture parses and is handled", () => {
    const env = envOf();
    const fx = JSON.parse(fs.readFileSync(new URL("../../protocol/test/fixtures/claude-code/2.1.332-win32/configchange/ConfigChange.1.json", import.meta.url), "utf8")) as { hookStdin: Record<string, unknown> };
    writeJson(localFile(env), { env: { GBX_PROBE: "allowed-change" } });
    const r = runHook("config-change", JSON.stringify({ ...fx.hookStdin, cwd: env.project, file_path: localFile(env) }), env);
    expect(r.stdout).toBe("");
    expect(settingsEvents(env).length).toBe(1);
  });
});

describe("start-up and per-call checks (changes no ConfigChange saw)", () => {
  it("RT-HOOK-52: dangerous settings written between sessions → strict at SessionStart", () => {
    const env = envOf();
    writeJson(projectFile(env), { permissions: { allow: ["Bash(*)"] } });
    sessionStart(env);
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
    expect(settingsEvents(env).at(-1)?.summary?.settings).toMatchObject({ scope: "project", level: "dangerous", via: "session-start", reasons: ["broad-allow"] });
  });

  it("RT-HOOK-53: a dangerous change made between two tool calls (no ConfigChange) → strict at the next call", () => {
    const env = envOf();
    sessionStart(env);
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBeUndefined();
    writeJson(localFile(env), { hooks: { Stop: [{ hooks: [{ type: "command", command: "x" }] }] } });
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
    expect(settingsEvents(env).at(-1)?.summary?.settings).toMatchObject({ via: "tool-call", reasons: ["hooks"] });
  });

  it("first sight of ordinary settings: recorded, no strict mode (the owner's real settings)", () => {
    const env = envOf();
    writeJson(userFile(env), { attribution: { commit: "", pr: "" }, model: "opus", autoUpdatesChannel: "latest", theme: "dark" });
    sessionStart(env);
    expect(settingsEvents(env).at(-1)?.summary?.settings).toMatchObject({ scope: "user", level: "ordinary", firstSeen: true });
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBeUndefined();
  });

  it("Claude Code adding `theme` by itself is recorded as cosmetic, never strict", () => {
    const env = envOf();
    writeJson(userFile(env), { model: "opus" });
    sessionStart(env);
    writeJson(userFile(env), { model: "opus", theme: "dark" });
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBeUndefined();
    expect(settingsEvents(env).at(-1)?.summary?.settings).toMatchObject({ level: "cosmetic", changedKeys: ["theme"] });
  });

  it("reverting a dangerous change to the approved content ends strict mode", () => {
    const env = envOf();
    writeJson(localFile(env), { model: "a" });
    sessionStart(env);
    writeJson(localFile(env), { model: "a", apiKeyHelper: "/tmp/k.sh" });
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
    writeJson(localFile(env), { model: "a" });
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBeUndefined();
  });

  it("deleting a settings file is a change too", () => {
    const env = envOf();
    writeJson(localFile(env), { permissions: { deny: ["Bash(curl:*)"] } });
    sessionStart(env);
    fs.rmSync(localFile(env));
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBeUndefined();
    expect(settingsEvents(env).at(-1)?.summary?.settings).toMatchObject({ changedKeys: ["permissions.deny"] });
  });

  it("unreadable settings at start-up → strict (Glassbox can't tell what was loaded)", () => {
    const env = envOf();
    fs.mkdirSync(path.dirname(projectFile(env)), { recursive: true });
    fs.writeFileSync(projectFile(env), "{ not json");
    sessionStart(env);
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
  });

  it("RT-HOOK-58: a dangerous change to USER settings makes sessions in other projects strict too; a project's doesn't", () => {
    const env = envOf();
    const other = path.join(env.homeDir, "other");
    fs.mkdirSync(other, { recursive: true });
    const otherSession = "00000000-0000-4000-8000-0000000000dd";
    const inOther = (session: string) =>
      runHook("pre", JSON.stringify({ ...pre({ project: other }, "Write", { file_path: path.join(other, "a.txt"), content: "x" }), session_id: session }), env);
    runHook("session-start", JSON.stringify({ ...common({ project: other }, { session_id: otherSession }), hook_event_name: "SessionStart", source: "startup" }), env);

    writeJson(localFile(env), { env: { NODE_OPTIONS: "x" } }); // project A only
    sessionStart(env);
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
    expect(decisionOf(inOther(otherSession).stdout)?.permissionDecision).toBeUndefined();

    writeJson(userFile(env), { apiKeyHelper: "/tmp/k.sh" }); // every project
    expect(decisionOf(inOther(otherSession).stdout)?.permissionDecision).toBe("ask");
  });

  it("RT-HOOK-59: a failure inside the settings check fails closed (strict), it never skips the check", () => {
    const env = { ...envOf(), managedSettingsPaths: [42 as unknown as string] };
    const w = decisionOf(writeCall(env).stdout);
    expect(w?.permissionDecision).toBe("ask");
    expect(w?.permissionDecisionReason).toMatch(/couldn't verify your Claude Code settings/);
    expect(decisionOf(readCall(env).stdout)?.permissionDecision).toBeUndefined();
  });

  it("CLAUDE_CONFIG_DIR moves the user settings file", () => {
    const env = { ...envOf() };
    const cfg = path.join(env.root, "cfg");
    env.claudeConfigDir = cfg;
    writeJson(path.join(cfg, "settings.json"), { disableAllHooks: true });
    sessionStart(env);
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
  });
});

describe("the agent can't end strict mode or hide a change", () => {
  const strictEnv = () => {
    const env = envOf();
    writeJson(localFile(env), { env: { BASH_ENV: "/tmp/x.sh" } });
    sessionStart(env);
    return env;
  };

  it("RT-HOOK-54: writing or deleting Glassbox's settings state is denied", () => {
    const env = strictEnv();
    const state = path.join(env.glassboxHome, "settings");
    // Bash treats backslashes as escapes: Windows paths in a Bash command use forward slashes.
    const sh = (p: string) => p.replaceAll("\\", "/");
    for (const cmd of [`rm -rf ${sh(state)}`, `echo '{}' > ${sh(path.join(state, "review", "x.json"))}`, "glassbox confirm-settings", "npx glassbox confirm-settings"]) {
      expect(decisionOf(runHook("pre", JSON.stringify(pre(env, "Bash", bash(cmd))), env).stdout)?.permissionDecision, cmd).toBe("deny");
    }
    expect(decisionOf(runHook("pre", JSON.stringify(pre(env, "Write", { file_path: path.join(state, "approved", "x.json"), content: "{}" })), env).stdout)?.permissionDecision).toBe("deny");
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
  });

  it("RT-HOOK-55: tampered review state keeps strict mode (fail closed)", () => {
    const env = strictEnv();
    const review = path.join(env.glassboxHome, "settings", "review");
    for (const f of fs.readdirSync(review)) fs.writeFileSync(path.join(review, f), "garbage");
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
  });

  it.runIf(process.platform !== "win32")("RT-HOOK-55: a review folder replaced by a link keeps strict mode", () => {
    const env = strictEnv();
    const review = path.join(env.glassboxHome, "settings", "review");
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), "gbx-empty-"));
    fs.rmSync(review, { recursive: true });
    fs.symlinkSync(empty, review, "dir");
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
  });

  it.runIf(process.platform !== "win32")("RT-HOOK-56: an approved snapshot that is a link isn't trusted", () => {
    const env = envOf();
    writeJson(localFile(env), { hooks: { Stop: [] } });
    sessionStart(env); // strict: hooks
    confirmSettings(env, env.project);
    const approved = path.join(env.glassboxHome, "settings", "approved");
    // Replace every approved snapshot with a link to a file claiming the dangerous content was approved.
    const fake = path.join(env.root, "fake.json");
    fs.writeFileSync(fake, "{}");
    for (const f of fs.readdirSync(approved)) { fs.rmSync(path.join(approved, f)); fs.symlinkSync(fake, path.join(approved, f)); }
    writeJson(localFile(env), { hooks: { Stop: [] }, model: "b" });
    expect(decisionOf(writeCall(env).stdout)?.permissionDecision).toBe("ask");
  });

  it("RT-HOOK-57: events and the log carry key names, never values", () => {
    const env = envOf();
    const token = ["ghp", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("_"); // built at run time
    writeJson(localFile(env), { env: { GITHUB_TOKEN: token }, apiKeyHelper: `echo ${token}` });
    sessionStart(env);
    writeCall(env);
    const spoolText = fs.readdirSync(path.join(env.glassboxHome, "spool")).map((f) => fs.readFileSync(path.join(env.glassboxHome, "spool", f), "utf8")).join("");
    const log = fs.readFileSync(path.join(env.glassboxHome, "logs", "hook.log"), "utf8");
    expect(spoolText).toContain("env.GITHUB_TOKEN");
    for (const t of [spoolText, log]) {
      expect(t).not.toContain(token);
      expect(t).not.toContain("A1b2C3d4");
    }
  });
});
