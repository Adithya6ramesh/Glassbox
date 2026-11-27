// Config and the engine SessionContext, built only from local state the agent can't write
// (~/.glassbox is protected by the engine) plus the hook payload.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as v from "valibot";
import { ACTION_TAGS, EMBEDDED_BASELINE, type ApprovalMode, type RememberedRule, type SessionContext } from "@glassbox-ai/engine";
import type { OutputFlags } from "./reply.js";
import type { Store } from "./store.js";

export interface HookEnv {
  /** The user's home folder (from the hook's command line, else os.homedir()). */
  homeDir: string;
  /** ~/.glassbox */
  glassboxHome: string;
  platform: "linux" | "darwin" | "win32";
  /** CLAUDE_PLUGIN_ROOT: protected as well (only ever adds protection). */
  pluginRoot?: string | undefined;
  /** CLAUDE_CONFIG_DIR: protected as well; the engine always protects ~/.claude too. */
  claudeConfigDir?: string | undefined;
  /**
   * Managed-settings files to watch. Default: Claude Code's documented location for the platform.
   * Never taken from the environment (a repository's settings can set environment variables).
   */
  managedSettingsPaths?: string[] | undefined;
  /** performance.now() when the hook process started its own code. */
  startedAtMs?: number | undefined;
}

export interface Config {
  mode: ApprovalMode;
  flags: OutputFlags;
  degradedReasons: string[];
}

const ConfigSchema = v.object({
  mode: v.optional(v.picklist(["autopilot", "balanced", "strict"])),
  experimental: v.optional(v.object({ unverifiedHookOutputs: v.optional(v.boolean()) })),
});

const RememberedSchema = v.pipe(
  v.array(v.object({
    projectIdHash: v.pipe(v.string(), v.regex(/^[0-9a-f]{64}$/)),
    serverId: v.pipe(v.string(), v.minLength(1), v.maxLength(128)),
    toolName: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
    actionTag: v.picklist(ACTION_TAGS),
    createdAt: v.string(),
  })),
  v.maxLength(1000),
);

/** Missing config → defaults. Unreadable or invalid → defaults (balanced, flags off) and a degraded mark. */
export function loadConfig(store: Store): Config {
  const r = store.readJson("config.json");
  if (!r.found) return { mode: "balanced", flags: { unverifiedHookOutputs: false }, degradedReasons: [] };
  // A link or another user's file is never trusted: defaults (balanced, flags off), recorded.
  if (r.unsafe) return { mode: "balanced", flags: { unverifiedHookOutputs: false }, degradedReasons: ["config-unsafe"] };
  const parsed = r.error ? null : v.safeParse(ConfigSchema, r.value);
  if (!parsed?.success) return { mode: "balanced", flags: { unverifiedHookOutputs: false }, degradedReasons: ["config-invalid"] };
  return {
    mode: parsed.output.mode ?? "balanced",
    flags: { unverifiedHookOutputs: parsed.output.experimental?.unverifiedHookOutputs === true },
    degradedReasons: [],
  };
}

export function loadRemembered(store: Store): { rules: RememberedRule[]; degradedReasons: string[] } {
  const r = store.readJson("remembered.json");
  if (!r.found) return { rules: [], degradedReasons: [] };
  if (r.unsafe) return { rules: [], degradedReasons: ["remembered-unsafe"] };
  const parsed = r.error ? null : v.safeParse(RememberedSchema, r.value);
  return parsed?.success ? { rules: parsed.output, degradedReasons: [] } : { rules: [], degradedReasons: ["remembered-invalid"] };
}

const caseInsensitive = (p: HookEnv["platform"]) => p === "win32" || p === "darwin";

function realpathOr(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

/** HMAC-SHA256 of the project's real path under the device salt, and a display label. */
export function projectOf(cwd: string, env: HookEnv, store: Store): { idHash: string; label: string } {
  let real = path.resolve(realpathOr(cwd));
  if (caseInsensitive(env.platform)) real = real.toLowerCase();
  const idHash = crypto.createHmac("sha256", store.salt()).update(real).digest("hex");
  const base = path.basename(cwd).replace(/[\u0000-\u001f\\/]/g, "").slice(0, 64);
  return { idHash, label: base || "project" };
}

const PATH_KEYS = ["file_path", "notebook_path", "path"];

/**
 * Real paths of existing path arguments, so a write through an earlier-created symlink is
 * caught. The engine looks paths up in its own normalized form, so equivalent spellings are
 * all supplied. Paths that don't exist are skipped (no realpath on them).
 */
export function resolvedPathsFor(input: Record<string, unknown>, cwd: string, env: HookEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of PATH_KEYS) {
    const raw = input[k];
    if (typeof raw !== "string" || raw.length === 0 || raw.length > 4096) continue;
    const abs = path.resolve(cwd, raw);
    let real: string;
    try {
      real = fs.realpathSync.native(abs);
    } catch {
      continue;
    }
    if (real === abs) continue;
    const keys = new Set([raw, abs, raw.replaceAll("\\", "/"), abs.replaceAll("\\", "/")]);
    if (caseInsensitive(env.platform)) for (const key of [...keys]) keys.add(key.toLowerCase());
    for (const key of keys) out[key] = real;
  }
  return out;
}

export function buildContext(a: {
  sessionId: string; cwd: string; toolInput: Record<string, unknown>; env: HookEnv; store: Store; config: Config;
  projectIdHash: string; remembered: RememberedRule[];
  /** The engine's time limit for this check (the engine's own default is 100 ms). */
  hardStopMs: number;
}): SessionContext {
  const { env } = a;
  // The working folder in its real long form. On Windows it can arrive as an 8.3 short name
  // (C:\Users\RUNNER~1\...); the engine can't rule out that a short-name segment hides a
  // protected folder, so every relative write would be denied. Resolving it also follows
  // junctions and symlinks, so a project folder that is really a link into ~/.claude is seen
  // as ~/.claude. The home and Glassbox folders stay as given: writes through their short or
  // linked spellings are already denied by the engine, and changing them could only unprotect.
  const cwd = realpathOr(a.cwd);
  const glassboxDirs = [env.glassboxHome, ...(env.pluginRoot ? [env.pluginRoot] : [])];
  return {
    sessionId: a.sessionId,
    platform: env.platform,
    ...(env.claudeConfigDir ? { claudeConfigDir: env.claudeConfigDir } : {}),
    glassboxSecretPaths: [path.join(env.glassboxHome, "device.key"), path.join(env.glassboxHome, "device-salt")],
    projectIdHash: a.projectIdHash,
    remembered: a.remembered,
    homeDir: env.homeDir,
    cwd,
    caseInsensitiveFs: caseInsensitive(env.platform),
    glassboxDirs,
    resolvedPaths: resolvedPathsFor(a.toolInput, cwd, env),
    servers: [],
    signals: a.store.readSignals(a.sessionId),
    policy: { mode: a.config.mode },
    // Steps 2-3: no rules cache is ever written; the embedded baseline is always used.
    ruleset: EMBEDDED_BASELINE,
    limits: { hardStopMs: a.hardStopMs },
  };
}
