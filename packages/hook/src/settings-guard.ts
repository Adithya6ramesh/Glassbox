// Watching Claude Code's settings files (Phase 2 Step 2).
//
// Observed live with Claude Code 2.1.332: ConfigChange names the changed file but carries no
// content; a block keeps the session's previous settings but leaves the file on disk; and files
// written while no session runs fire no event and are loaded at the next start. So the hook keeps
// its own copy of the last approved version of each settings file and judges every change
// against it, at three points:
//   - ConfigChange: block changes that would stop Glassbox running, block a burst of changes or
//     a file that changes while it is checked, otherwise record (and start strict mode when the
//     change is dangerous);
//   - SessionStart: everything that changed while no session ran;
//   - before every tool call: a cheap stat of each file, so a change no event reported is caught.
// A dangerous change puts every session that loads that file in strict mode (every non-read
// tool asks) until the user confirms it in a terminal (`glassbox confirm-settings`, Step 3).
// Glassbox never rewrites a settings file itself.
//
//   ~/.glassbox/settings/approved/<k>.json   last approved bytes of a settings file
//   ~/.glassbox/settings/seen/<k>.json       size/mtime/ctime/sha of the last check (fast path)
//   ~/.glassbox/settings/review/<k>.json     a dangerous change waiting for confirmation (strict)
//   ~/.glassbox/settings/blocked/<k>-<h>.json content ConfigChange blocked, and in which session
//   ~/.glassbox/settings/changes/<k>.json    recent change times (burst rule)
// <k> = first 32 hex of SHA-256 of the file's path. The engine denies the agent any write under
// ~/.glassbox, and nothing here is trusted unless it is a regular file owned by this user.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isPlainRecord } from "@glassbox-ai/protocol";
import type { HookEnv } from "./context.js";
import { classifySettingsChange, MAX_SETTINGS_BYTES, parseSettingsBytes, type SettingsClassification, type SettingsReason } from "./settings-classify.js";

export type SettingsScope = "user" | "project" | "local" | "managed";
export interface SettingsFile { scope: SettingsScope; path: string }
export type Via = "config-change" | "session-start" | "tool-call";

/** What a check found, for a settings_change event (key names only). */
export interface SettingsRecord {
  scope: SettingsScope | "skills" | "unknown";
  level: "unchanged" | "cosmetic" | "ordinary" | "dangerous";
  action: "allowed" | "blocked" | "strict" | "reverted";
  via: Via;
  changedKeys: string[];
  reasons: (SettingsReason | "burst" | "changed-while-checked")[];
  firstSeen?: boolean;
  blockedEarlier?: boolean;
}

/** More than this many changes to one file within BURST_WINDOW_MS are blocked. */
export const BURST_MAX = 3;
export const BURST_WINDOW_MS = 5000;

const MANAGED_DEFAULTS: Record<HookEnv["platform"], string> = {
  win32: "C:\\Program Files\\ClaudeCode\\managed-settings.json",
  darwin: "/Library/Application Support/ClaudeCode/managed-settings.json",
  linux: "/etc/claude-code/managed-settings.json",
};

/** The settings files a session in `projectRoot` loads (Claude Code's documented locations). */
export function settingsFiles(env: HookEnv, projectRoot: string): SettingsFile[] {
  const userDir = env.claudeConfigDir ?? path.join(env.homeDir, ".claude");
  const managed = env.managedSettingsPaths ?? [MANAGED_DEFAULTS[env.platform]];
  const out: SettingsFile[] = [
    { scope: "user", path: path.join(userDir, "settings.json") },
    { scope: "project", path: path.join(projectRoot, ".claude", "settings.json") },
    { scope: "local", path: path.join(projectRoot, ".claude", "settings.local.json") },
  ];
  for (const m of managed) {
    out.push({ scope: "managed", path: m });
    // Drop-ins: managed-settings.d/*.json next to managed-settings.json.
    const dir = path.join(path.dirname(m), "managed-settings.d");
    try {
      for (const n of fs.readdirSync(dir).filter((x) => x.endsWith(".json")).sort()) out.push({ scope: "managed", path: path.join(dir, n) });
    } catch {
      // none
    }
  }
  return out;
}

const caseInsensitive = (env: HookEnv) => env.platform !== "linux";
const fileKey = (env: HookEnv, p: string) => {
  const abs = path.resolve(p);
  return crypto.createHash("sha256").update(caseInsensitive(env) ? abs.toLowerCase() : abs).digest("hex").slice(0, 32);
};
const sha256 = (b: Buffer) => crypto.createHash("sha256").update(b).digest("hex");
const myUid = (): number | null => (typeof process.getuid === "function" ? process.getuid() : null);

// ── Glassbox's own state (never follow a link, never trust another user's file) ─────────────

type StateRead = { kind: "missing" } | { kind: "unsafe" } | { kind: "ok"; value: Record<string, unknown> };

function readState(file: string, max = 4 * MAX_SETTINGS_BYTES): StateRead {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(file);
  } catch {
    return { kind: "missing" };
  }
  const uid = myUid();
  if (!st.isFile() || (uid !== null && st.uid !== uid) || st.size > max) return { kind: "unsafe" };
  try {
    const v: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
    return isPlainRecord(v) ? { kind: "ok", value: v } : { kind: "unsafe" };
  } catch {
    return { kind: "unsafe" };
  }
}

/** A state folder that is missing or a real folder of ours; never a link. */
function dirState(dir: string): "missing" | "ok" | "unsafe" {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(dir);
  } catch {
    return "missing";
  }
  const uid = myUid();
  return st.isDirectory() && !st.isSymbolicLink() && (uid === null || st.uid === uid) ? "ok" : "unsafe";
}

function writeState(dir: string, name: string, value: unknown): void {
  const root = path.dirname(dir);
  if (dirState(root) === "unsafe" || dirState(dir) === "unsafe") return; // never write through a link
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `.${name}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify(value), { flag: "wx", mode: 0o600 });
  fs.renameSync(tmp, path.join(dir, name));
}

function removeState(file: string): void {
  try {
    if (fs.lstatSync(file).isFile()) fs.unlinkSync(file);
  } catch {
    // already gone
  }
}

class State {
  readonly root: string;
  constructor(glassboxHome: string) {
    this.root = path.join(glassboxHome, "settings");
  }
  dir(name: "approved" | "seen" | "review" | "blocked" | "changes") {
    return path.join(this.root, name);
  }

  /** The approved bytes, or null if there are none or they can't be trusted (`unsafe` says which). */
  approved(k: string): { sha: string; value: Record<string, unknown> } | null | "unsafe" {
    const r = readState(path.join(this.dir("approved"), `${k}.json`));
    if (r.kind === "missing") return null;
    if (r.kind === "unsafe" || typeof r.value["content"] !== "string") return "unsafe";
    const bytes = Buffer.from(r.value["content"], "base64");
    const p = parseSettingsBytes(bytes);
    return p.ok ? { sha: sha256(bytes), value: p.value } : "unsafe";
  }
  approve(k: string, file: string, bytes: Buffer | null): void {
    if (bytes === null) removeState(path.join(this.dir("approved"), `${k}.json`));
    else writeState(this.dir("approved"), `${k}.json`, { v: 1, path: file, content: bytes.toString("base64"), at: new Date(Date.now()).toISOString() });
    removeState(path.join(this.dir("review"), `${k}.json`));
  }

  seen(k: string): Record<string, unknown> | null {
    const r = readState(path.join(this.dir("seen"), `${k}.json`), 4096);
    return r.kind === "ok" ? r.value : null;
  }
  setSeen(k: string, v: Record<string, unknown>): void {
    writeState(this.dir("seen"), `${k}.json`, v);
  }

  review(k: string, entry: Record<string, unknown>): void {
    writeState(this.dir("review"), `${k}.json`, entry);
  }
  hasReview(k: string): boolean {
    return readState(path.join(this.dir("review"), `${k}.json`)).kind !== "missing";
  }

  blocked(k: string, sha: string): { sessionId: string } | null {
    const r = readState(path.join(this.dir("blocked"), `${k}-${sha.slice(0, 16)}.json`), 4096);
    return r.kind === "ok" && r.value["sha256"] === sha && typeof r.value["sessionId"] === "string" ? { sessionId: r.value["sessionId"] } : null;
  }
  setBlocked(k: string, sha: string, sessionId: string): void {
    writeState(this.dir("blocked"), `${k}-${sha.slice(0, 16)}.json`, { sha256: sha, sessionId, at: new Date(Date.now()).toISOString() });
  }

  /** Record a change now; return how many changes fell inside the burst window (this one included). */
  changeCount(k: string, nowMs: number): number {
    const r = readState(path.join(this.dir("changes"), `${k}.json`), 4096);
    const prev = r.kind === "ok" && Array.isArray(r.value["times"]) ? (r.value["times"] as unknown[]).filter((t): t is number => typeof t === "number") : [];
    const times = [...prev.filter((t) => nowMs - t >= 0 && nowMs - t < BURST_WINDOW_MS), nowMs].slice(-20);
    try {
      writeState(this.dir("changes"), `${k}.json`, { times });
    } catch {
      // a lost entry only makes the rule less strict for one change
    }
    return times.length;
  }
}

// ── Reading a settings file (as Claude Code does: links are followed) ──────────────────────

type FileRead = { kind: "missing" } | { kind: "unreadable" } | { kind: "ok"; bytes: Buffer };
export type FileReader = (file: string) => Buffer | null;

/** Default reader: a regular file (links followed), at most MAX_SETTINGS_BYTES + 1 bytes read. */
export function readSettingsFile(file: string): Buffer | null {
  let fd: number;
  try {
    fd = fs.openSync(file, "r");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT" || (e as NodeJS.ErrnoException).code === "ENOTDIR") return null;
    throw e;
  }
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Error("not a regular file");
    const buf = Buffer.alloc(MAX_SETTINGS_BYTES + 1);
    let n = 0;
    for (;;) {
      const r = fs.readSync(fd, buf, n, buf.length - n, null);
      if (r === 0) break;
      n += r;
      if (n >= buf.length) break;
    }
    return buf.subarray(0, n);
  } finally {
    fs.closeSync(fd);
  }
}

function readFile(read: FileReader, file: string): FileRead {
  try {
    const b = read(file);
    return b === null ? { kind: "missing" } : { kind: "ok", bytes: b };
  } catch {
    return { kind: "unreadable" };
  }
}

const statKey = (file: string): Record<string, unknown> => {
  try {
    const st = fs.statSync(file, { bigint: true });
    return { size: String(st.size), mtime: String(st.mtimeNs), ctime: String(st.ctimeNs), ino: String(st.ino) };
  } catch {
    return { missing: true };
  }
};
const sameStat = (a: Record<string, unknown> | null, b: Record<string, unknown>) =>
  a !== null && ["size", "mtime", "ctime", "ino", "missing"].every((k) => a[k] === b[k]);

// ── Judging one file ───────────────────────────────────────────────────────────────────────

interface Judged { record: SettingsRecord | null; strict: boolean }

/**
 * Judge a file's current content against its approved snapshot and apply the result: approve
 * (not dangerous), start strict mode (dangerous), or clear strict mode (back to approved content).
 */
function judge(env: HookEnv, st: State, f: SettingsFile, cur: FileRead, via: Via, sessionId: string): Judged {
  const k = fileKey(env, f.path);
  const appr = st.approved(k);
  const approved = appr === "unsafe" ? null : appr; // an untrusted snapshot counts as none: compare with {}
  const curSha = cur.kind === "ok" ? sha256(cur.bytes) : null;

  // Back to (or still at) the approved content: nothing to judge; strict mode for it ends.
  if ((approved && curSha === approved.sha) || (cur.kind === "missing" && approved === null && appr !== "unsafe")) {
    const hadReview = st.hasReview(k);
    if (hadReview) removeState(path.join(st.dir("review"), `${k}.json`));
    return { record: hadReview ? { scope: f.scope, level: "unchanged", action: "reverted", via, changedKeys: [], reasons: [] } : null, strict: false };
  }

  const blocked = curSha !== null ? st.blocked(k, curSha) : null;
  // Content ConfigChange blocked in THIS session isn't loaded in it (the block kept the old settings).
  if (blocked && blocked.sessionId === sessionId && via === "tool-call") return { record: null, strict: false };

  const parsed = cur.kind === "ok" ? parseSettingsBytes(cur.bytes) : null;
  const after = cur.kind === "missing" ? {} : parsed?.ok ? parsed.value : null;
  const c: SettingsClassification = classifySettingsChange(approved?.value ?? {}, after);
  const base = { scope: f.scope, level: c.level, via, changedKeys: c.changedKeys, reasons: c.reasons, ...(approved === null ? { firstSeen: true } : {}), ...(blocked ? { blockedEarlier: true } : {}) } as const;

  if (c.level === "dangerous") {
    st.review(k, { v: 1, path: f.path, scope: f.scope, sha256: curSha, level: c.level, reasons: c.reasons, changedKeys: c.changedKeys, blockedEarlier: blocked !== null, foundAt: new Date(Date.now()).toISOString() });
    return { record: { ...base, action: "strict" }, strict: true };
  }
  st.approve(k, f.path, cur.kind === "ok" ? cur.bytes : null);
  return { record: c.level === "unchanged" ? null : { ...base, action: "allowed" }, strict: false };
}

// ── The three checks ───────────────────────────────────────────────────────────────────────

export interface StrictInfo { reason: string }
export interface CheckResult { records: SettingsRecord[]; strict: StrictInfo | null; degraded: string[] }

const SCOPE_LABEL: Record<SettingsScope, string> = { user: "user", project: "project", local: "local project", managed: "managed" };

/** Strict mode when the settings can't be checked at all (fail closed). */
export const SETTINGS_UNVERIFIED_REASON = "Glassbox: it couldn't verify your Claude Code settings. Every action needs your approval until you run `glassbox confirm-settings` in a terminal.";

function strictReason(entries: Record<string, unknown>[]): string {
  const e = entries[0];
  if (!e) return SETTINGS_UNVERIFIED_REASON;
  const scope = typeof e["scope"] === "string" && Object.hasOwn(SCOPE_LABEL, e["scope"]) ? SCOPE_LABEL[e["scope"] as SettingsScope] : "Claude Code";
  const keys = Array.isArray(e["changedKeys"]) ? (e["changedKeys"] as unknown[]).filter((x): x is string => typeof x === "string").slice(0, 3) : [];
  const what = keys.length > 0 ? ` (${keys.join(", ")})` : "";
  const earlier = e["blockedEarlier"] === true ? " A change Glassbox blocked earlier is now loaded." : "";
  return `Glassbox: your ${scope} settings changed${what} in a way that needs your review.${earlier} Every action needs your approval until you run \`glassbox confirm-settings\` in a terminal.`;
}

/**
 * Strict mode applies while a review entry exists for a file this session loads. Untrustworthy
 * review state (a link, another user's file, garbage) also means strict: fail closed.
 */
function pendingReviews(env: HookEnv, st: State, files: SettingsFile[]): { strict: boolean; entries: Record<string, unknown>[] } {
  const dir = st.dir("review");
  const ds = dirState(st.root) === "unsafe" ? "unsafe" : dirState(dir);
  if (ds === "missing") return { strict: false, entries: [] };
  if (ds === "unsafe") return { strict: true, entries: [] };
  const mine = new Set(files.map((f) => fileKey(env, f.path)));
  let names: string[];
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith(".json"));
  } catch {
    return { strict: true, entries: [] };
  }
  let strict = false;
  const entries: Record<string, unknown>[] = [];
  for (const n of names) {
    const r = readState(path.join(dir, n));
    if (r.kind === "missing") continue;
    if (r.kind === "unsafe") { strict = true; continue; }
    const scope = r.value["scope"];
    // User and managed settings apply to every session; project files only to their project.
    if (scope === "user" || scope === "managed" || mine.has(n.slice(0, -5)) || typeof scope !== "string") {
      strict = true;
      entries.push(r.value);
    }
  }
  return { strict, entries };
}

/**
 * SessionStart (`via: "session-start"`: every file is read) or before a tool call
 * (`via: "tool-call"`: a file is read only when its size/times changed since the last check).
 */
export function checkSettings(env: HookEnv, a: { sessionId: string; projectRoot: string; via: "session-start" | "tool-call" }, read: FileReader = readSettingsFile): CheckResult {
  const st = new State(env.glassboxHome);
  const files = settingsFiles(env, a.projectRoot);
  const records: SettingsRecord[] = [];
  const degraded: string[] = [];
  for (const f of files) {
    const k = fileKey(env, f.path);
    const now = statKey(f.path);
    if (a.via === "tool-call" && sameStat(st.seen(k), now)) continue;
    if (st.approved(k) === "unsafe" && !degraded.includes("settings-state-unsafe")) degraded.push("settings-state-unsafe");
    const j = judge(env, st, f, readFile(read, f.path), a.via, a.sessionId);
    if (j.record) records.push(j.record);
    try {
      st.setSeen(k, now);
    } catch {
      // the next call reads the file again
    }
  }
  const p = pendingReviews(env, st, files);
  return { records, strict: p.strict ? { reason: strictReason(p.entries) } : null, degraded };
}

const SOURCE_SCOPE: Record<string, SettingsScope | "skills"> = {
  user_settings: "user", project_settings: "project", local_settings: "local", policy_settings: "managed", skills: "skills",
};

/**
 * ConfigChange. Returns the reason to block (null: allow) and what to record. `file_path` from
 * the payload is NOT trusted to pick the file: the source decides, so a payload can't point the
 * check at a harmless decoy. Policy settings can't be blocked (Claude Code ignores it): recorded.
 */
export function onConfigChange(
  env: HookEnv,
  a: { sessionId: string; cwd: string; projectRoot?: string; source: string; filePath?: string },
  read: FileReader = readSettingsFile,
): { block: string | null; records: SettingsRecord[] } {
  const scope = (Object.hasOwn(SOURCE_SCOPE, a.source) ? SOURCE_SCOPE[a.source] : undefined) ?? "unknown";
  if (scope === "skills") return { block: null, records: [{ scope: "skills", level: "ordinary", action: "allowed", via: "config-change", changedKeys: [], reasons: [] }] };
  const st = new State(env.glassboxHome);
  const files = settingsFiles(env, a.projectRoot ?? a.cwd);
  const targets = scope === "unknown" ? files.filter((f) => f.scope !== "managed") : files.filter((f) => f.scope === scope);
  const canBlock = scope !== "managed";
  const records: SettingsRecord[] = [];
  let block: string | null = null;

  for (const f of targets) {
    const k = fileKey(env, f.path);
    const blockWith = (reason: string, record: Omit<SettingsRecord, "action" | "via" | "scope">, sha: string | null) => {
      records.push({ scope: f.scope, via: "config-change", ...record, action: canBlock ? "blocked" : "strict" });
      if (!canBlock) return;
      if (sha) st.setBlocked(k, sha, a.sessionId);
      block ??= reason;
    };

    if (canBlock && st.changeCount(k, Date.now()) > BURST_MAX) {
      const cur = readFile(read, f.path);
      blockWith("Blocked by Glassbox: this settings file changed several times in quick succession.", { level: "dangerous", changedKeys: [], reasons: ["burst"] }, cur.kind === "ok" ? sha256(cur.bytes) : null);
      continue;
    }

    const first = readFile(read, f.path);
    const appr = st.approved(k);
    const approved = appr === "unsafe" ? null : appr;
    if (first.kind === "unreadable" || (first.kind === "ok" && !parseSettingsBytes(first.bytes).ok)) {
      blockWith("Blocked by Glassbox: it couldn't read this settings file as valid settings.", { level: "dangerous", changedKeys: [], reasons: ["unreadable"] }, first.kind === "ok" ? sha256(first.bytes) : null);
      continue;
    }
    const after = first.kind === "ok" ? (parseSettingsBytes(first.bytes) as { ok: true; value: Record<string, unknown> }).value : {};
    const c = classifySettingsChange(approved?.value ?? {}, after);
    if (c.block) {
      blockWith("Blocked by Glassbox: this settings change would turn off Glassbox's checks.", { level: c.level, changedKeys: c.changedKeys, reasons: c.reasons }, first.kind === "ok" ? sha256(first.bytes) : null);
      continue;
    }
    // Time of check vs time of use: re-read before allowing; a file that changed meanwhile is
    // blocked, and its newer content gets its own event.
    const second = readFile(read, f.path);
    const sameBytes = first.kind === second.kind && (first.kind !== "ok" || (second.kind === "ok" && sha256(first.bytes) === sha256(second.bytes)));
    if (!sameBytes) {
      blockWith("Blocked by Glassbox: the settings file changed while Glassbox was checking it.", { level: "dangerous", changedKeys: c.changedKeys, reasons: ["changed-while-checked"] }, second.kind === "ok" ? sha256(second.bytes) : null);
      continue;
    }
    const j = judge(env, st, f, first, "config-change", a.sessionId);
    if (j.record) records.push(j.record);
    try {
      st.setSeen(k, statKey(f.path));
    } catch {
      // read again next call
    }
  }
  return { block, records };
}

/**
 * Approve the current content of every file waiting for review (what `glassbox confirm-settings`
 * does after the user confirms in a terminal; Step 3). Returns how many files were approved.
 */
export function confirmSettings(env: HookEnv, projectRoot: string, read: FileReader = readSettingsFile): number {
  const st = new State(env.glassboxHome);
  let n = 0;
  for (const f of settingsFiles(env, projectRoot)) {
    const k = fileKey(env, f.path);
    if (!st.hasReview(k)) continue;
    const cur = readFile(read, f.path);
    if (cur.kind === "unreadable") continue;
    st.approve(k, f.path, cur.kind === "ok" ? cur.bytes : null);
    st.setSeen(k, statKey(f.path));
    n++;
  }
  return n;
}
