// Path normalization and the protected / protected-read / sensitive sets (engine-spec §7.2, §7.6).
// Purely lexical: the engine can't see the filesystem.
import { trimEndChars } from "../util/misc.js";

export interface PathCtx {
  platform: "linux" | "darwin" | "win32";
  homeDir: string;
  cwd: string | null; // null = unknown
  caseInsensitive: boolean;
  glassboxDirs: readonly string[];
  claudeConfigDir?: string | undefined;
  extraProtected: readonly string[];
  extraSensitive: readonly string[];
  secretPaths: readonly string[];
  resolved?: Readonly<Record<string, string>> | undefined;
}

export interface NormPath {
  /** Normalized absolute path, or null if not resolvable. */
  path: string | null;
  /** Known literal suffix (starts with "/") when the path is only partly known. */
  suffix: string | null;
  /** The path is relative and the cwd is unknown. */
  relativeUnknown: boolean;
  basename: string;
}

export function fold(s: string, ci: boolean): string {
  return ci ? s.toLowerCase() : s;
}

export function normalizeSlashes(p: string, win: boolean): string {
  let s = p;
  if (win) {
    s = s.replace(/\\/g, "/");
    if (s.startsWith("//?/") || s.startsWith("//./")) s = s.slice(4);
    const m = /^\/\/(localhost|127\.0\.0\.1)\/([a-zA-Z])\$\//i.exec(s.slice(0, 40));
    if (m) s = `${m[2] as string}:/` + s.slice(m[0].length);
  }
  return s;
}

/** Collapse //, ., .. (lexically, never above root); strip Windows segment tricks. */
function collapse(p: string, win: boolean): string {
  let root = "";
  let rest = p;
  const drive = /^([a-zA-Z]):(\/|$)/.exec(p.slice(0, 3));
  if (win && drive) { root = (drive[1] as string).toLowerCase() + ":/"; rest = p.slice(drive[0].length); }
  else if (p.startsWith("/")) { root = "/"; rest = p.slice(1); }
  const out: string[] = [];
  const segs = rest.split("/");
  segs.forEach((seg0, idx) => {
    let seg = seg0;
    if (win) {
      if (idx === segs.length - 1) seg = seg.replace(/::\$DATA$/i, "").replace(/:[^:/]*$/, "");
      seg = seg === "." || seg === ".." ? seg : trimEndChars(seg, ". ");
    }
    if (seg === "" || seg === ".") return;
    if (seg === "..") { out.pop(); return; }
    out.push(seg);
  });
  return root + out.join("/");
}

function expandHome(p: string, home: string): { s: string; unknownUser: boolean } {
  const h = trimEndChars(home, "\\/");
  for (const pre of ["$HOME", "${HOME}", "%USERPROFILE%", "$env:USERPROFILE", "${env:USERPROFILE}", "%HOMEDRIVE%%HOMEPATH%"]) {
    if (p === pre || p.startsWith(pre + "/") || p.startsWith(pre + "\\")) return { s: h + p.slice(pre.length), unknownUser: false };
    if (p.toLowerCase().startsWith(pre.toLowerCase()) && pre.startsWith("$env:")) {
      const tail = p.slice(pre.length);
      if (tail === "" || tail.startsWith("/") || tail.startsWith("\\")) return { s: h + tail, unknownUser: false };
    }
  }
  if (p === "~" || p.startsWith("~/") || p.startsWith("~\\")) return { s: h + p.slice(1), unknownUser: false };
  if (p.startsWith("~")) return { s: p, unknownUser: true };
  return { s: p, unknownUser: false };
}

function isAbsolute(p: string, win: boolean): boolean {
  return p.startsWith("/") || (win && /^[a-zA-Z]:\//.test(p.slice(0, 3)));
}

export function normalizeFull(raw: string, ctx: PathCtx): string | null {
  const win = ctx.platform === "win32";
  const { s: expanded, unknownUser } = expandHome(raw, ctx.homeDir);
  if (unknownUser) return null;
  let s = normalizeSlashes(expanded, win);
  if (!isAbsolute(s, win)) {
    if (ctx.cwd === null) return null;
    s = trimEndChars(normalizeSlashes(ctx.cwd, win), "/") + "/" + s;
  }
  s = collapse(s, win);
  s = s.normalize("NFC");
  return fold(s, ctx.caseInsensitive);
}

export function normalizePath(raw: string, ctx: PathCtx): NormPath {
  const win = ctx.platform === "win32";
  const slashed = normalizeSlashes(raw, win);
  const base = slashed.split("/").filter(Boolean).pop() ?? "";
  const path = normalizeFull(raw, ctx);
  const relativeUnknown = path === null && !raw.startsWith("~") && !isAbsolute(normalizeSlashes(expandHome(raw, ctx.homeDir).s, win), win);
  let suffix: string | null = null;
  if (path === null) suffix = fold("/" + collapse(slashed.replace(/^~[^/]*\/?/, ""), win).replace(/^\/+/, ""), ctx.caseInsensitive);
  return { path, suffix, relativeUnknown, basename: fold(trimEndChars(base, ". "), ctx.caseInsensitive) };
}

/** A path known only by its literal tail (e.g. "$(…)/.claude/settings.json"). */
export function suffixOnly(tail: string, ctx: PathCtx): NormPath {
  const win = ctx.platform === "win32";
  const t = collapse(normalizeSlashes(tail, win), win);
  const suffix = fold(t.startsWith("/") ? t : "/" + t, ctx.caseInsensitive);
  return { path: null, suffix, relativeUnknown: false, basename: suffix.split("/").pop() ?? "" };
}

// ── The sets ─────────────────────────────────────────────────────────────

export interface Entry { p: string; dir: boolean }

export const ANYWHERE = ["/.claude/settings.json", "/.claude/settings.local.json", "/.mcp.json"];
const MANAGED = ["/etc/claude-code", "/library/application support/claudecode", "c:/program files/claudecode", "c:/programdata/claudecode"];
const PROTECTED_BASENAMES = ["settings.json", "settings.local.json", ".mcp.json", ".claude.json"];

export function entries(ctx: PathCtx): Entry[] {
  const n = (p: string) => normalizeFull(p, { ...ctx, cwd: "/" });
  const out: Entry[] = [];
  const add = (p: string | null, dir: boolean) => { if (p) out.push({ p, dir }); };
  for (const d of ctx.glassboxDirs) add(n(d), true);
  const configDirs = [ctx.claudeConfigDir, `${ctx.homeDir}/.claude`].filter((x): x is string => typeof x === "string" && x.length > 0);
  for (const c of configDirs) {
    add(n(`${c}/settings.json`), false);
    add(n(`${c}/settings.local.json`), false);
    add(n(`${c}/hooks`), true);
    add(n(`${c}/plugins`), true);
  }
  add(n(`${ctx.homeDir}/.claude.json`), false);
  for (const x of ctx.extraProtected) {
    const dir = x.endsWith("/**") || x.endsWith("\\**");
    add(n(dir ? x.slice(0, -3) : x), dir);
  }
  return out;
}

export function readProtectedEntries(ctx: PathCtx): Entry[] {
  const n = (p: string) => normalizeFull(p, { ...ctx, cwd: "/" });
  const out: Entry[] = [];
  for (const d of ctx.glassboxDirs) {
    const p = n(d);
    if (p) out.push({ p: p + "/*.key", dir: false });
  }
  const gb = n(`${ctx.homeDir}/.glassbox`);
  if (gb) out.push({ p: gb + "/*.key", dir: false });
  for (const s of ctx.secretPaths) { const p = n(s); if (p) out.push({ p, dir: false }); }
  return out;
}

function under(path: string, e: Entry): boolean {
  if (e.p.endsWith("/*.key")) {
    const dir = e.p.slice(0, -6);
    return path.startsWith(dir + "/") && path.endsWith(".key");
  }
  return path === e.p || (e.dir && path.startsWith(e.p.endsWith("/") ? e.p : e.p + "/"));
}

/** 8.3 short-name segments (e.g. CLAUDE~1) that could stand for a protected segment. */
function shortNameMatch(path: string, ents: Entry[]): boolean {
  const segs = path.split("/");
  const k = segs.findIndex((s) => /~\d/.test(s));
  if (k < 0) return false;
  const short = (segs[k] as string).toLowerCase().split("~")[0] ?? "";
  for (const e of ents) {
    const es = e.p.split("/");
    if (es.length <= k) continue;
    if (segs.slice(0, k).join("/").toLowerCase() !== es.slice(0, k).join("/").toLowerCase()) continue;
    const target = (es[k] as string).toLowerCase().replace(/^\.+/, "").replace(/[^a-z0-9]/g, "").slice(0, 6);
    if (short.length > 0 && target.startsWith(short.slice(0, 6))) return true;
  }
  return false;
}

export function isProtected(np: NormPath, ctx: PathCtx): boolean {
  const ents = entries(ctx);
  const win = ctx.platform === "win32";
  // Managed-settings directories are matched case-insensitively on every platform.
  const managed = (p: string) => { const l = p.toLowerCase(); return MANAGED.some((m) => l === m || l.startsWith(m + "/")); };
  const check = (p: string) => ents.some((e) => under(p, e)) || managed(p) || ANYWHERE.some((a) => p.endsWith(fold(a, ctx.caseInsensitive))) || (win && shortNameMatch(p, ents));
  if (np.path !== null) {
    if (check(np.path)) return true;
    const r = ctx.resolved?.[np.path];
    if (r) { const rp = normalizeFull(r, ctx); if (rp && check(rp)) return true; }
    return false;
  }
  if (np.suffix !== null) {
    const suf = np.suffix;
    if (ANYWHERE.some((a) => suf.endsWith(fold(a, ctx.caseInsensitive)))) return true;
    if (ents.some((e) => suf.endsWith(e.p.slice(e.p.lastIndexOf("/"))) && !e.dir)) return true;
    if (suf.includes("/.glassbox/") || suf.endsWith("/.glassbox") || suf.includes("/.claude/hooks") || suf.includes("/.claude/plugins")) return true;
  }
  if (np.relativeUnknown) {
    const gbNames = ctx.glassboxDirs.map((d) => fold(d.split(/[\\/]/).filter(Boolean).pop() ?? "", ctx.caseInsensitive));
    if (PROTECTED_BASENAMES.includes(np.basename) || gbNames.includes(np.basename)) return true;
  }
  return false;
}

export function isProtectedRead(np: NormPath, ctx: PathCtx): boolean {
  const ents = readProtectedEntries(ctx);
  if (np.path !== null) {
    if (ents.some((e) => under(np.path as string, e))) return true;
    const r = ctx.resolved?.[np.path];
    if (r) { const rp = normalizeFull(r, ctx); if (rp && ents.some((e) => under(rp, e))) return true; }
    return false;
  }
  if (np.suffix !== null) return np.suffix.endsWith("/device.key") || (np.suffix.includes("/.glassbox/") && np.suffix.endsWith(".key"));
  return np.relativeUnknown && np.basename === "device.key";
}

/** A directory-wide read rooted at `np` covers a protected-read path. */
export function coversProtectedRead(np: NormPath, ctx: PathCtx): boolean {
  if (isProtectedRead(np, ctx)) return true;
  if (np.path === null) return np.suffix !== null && (np.suffix.endsWith("/.glassbox") || np.suffix.includes("/.glassbox/"));
  const root = trimEndChars(np.path, "/");
  const ents = readProtectedEntries(ctx);
  return ents.some((e) => {
    const target = e.p.endsWith("/*.key") ? e.p.slice(0, -6) : e.p;
    return target === root || target.startsWith(root === "" ? "/" : root + "/") || root === "/";
  });
}

/** A glob pattern (e.g. Glob tool) that could match a protected-read path. */
export function globCoversProtectedRead(pattern: string, base: string | null, ctx: PathCtx): boolean {
  const full = base ? `${trimEndChars(base, "\\/")}/${pattern}` : pattern;
  const literalPrefix = full.split(/[*?[{]/)[0] ?? "";
  const np = normalizePath(literalPrefix.length > 0 ? literalPrefix : ".", ctx);
  if (coversProtectedRead(np, ctx)) return true;
  const lower = full.toLowerCase();
  return lower.includes(".glassbox") || (lower.includes("*.key") && np.path !== null && coversProtectedRead(np, ctx));
}

// ── Sensitive (reads) ────────────────────────────────────────────────────

const HOME_DIRS: [string, string][] = [
  [".ssh", "ssh-keys"], [".aws", "cloud-credentials"], [".config/gcloud", "cloud-credentials"], [".azure", "cloud-credentials"],
  [".gnupg", "gpg-keys"], [".config/google-chrome", "browser-profile"], [".mozilla/firefox", "browser-profile"],
  ["library/application support/google/chrome", "browser-profile"], ["appdata/local/google/chrome/user data", "browser-profile"],
  ["appdata/roaming/microsoft/credentials", "os-credentials"], ["appdata/local/microsoft/credentials", "os-credentials"],
];
const HOME_FILES: [string, string][] = [
  [".kube/config", "cloud-credentials"], [".docker/config.json", "registry-credentials"], [".netrc", "credentials"], [".npmrc", "registry-credentials"],
  [".pypirc", "registry-credentials"], [".git-credentials", "credentials"], [".config/gh/hosts.yml", "credentials"],
];

// Persistence locations (spec rev 6, Q3; rev 7): files that make code run later (login,
// boot, a schedule, every shell or git command) or grant remote access.
//  - "deny": remote access, scheduled jobs, boot and session autostart (CP-SELF-004, protected).
//  - "ask":  shell and PowerShell startup files and global git config (CP-SELF-005). People
//    edit these by hand routinely, so the user decides; autopilot denies (R15).
const DENY_HOME_FILES = [".ssh/rc", ".ssh/authorized_keys", ".ssh/authorized_keys2", ".ssh/config"];
const ASK_HOME_FILES = [
  ".bashrc", ".shrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout",
  ".kshrc", ".cshrc", ".tcshrc", ".xprofile", ".xinitrc", ".xsessionrc", ".config/fish/config.fish", ".gitconfig", ".config/git/config",
];
const DENY_HOME_DIRS = [".config/systemd/user", ".config/autostart", "library/launchagents", "appdata/roaming/microsoft/windows/start menu/programs/startup"];
const ASK_HOME_DIRS = [".config/fish/conf.d", ".config/git/hooks", ".config/powershell", "documents/windowspowershell", "documents/powershell"];
const DENY_SYSTEM = [
  "/etc/cron", "/var/spool/cron/", "/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/", "/library/launchagents/",
  "/library/launchdaemons/", "/etc/rc.local", "/etc/ld.so.preload", "/etc/init.d/", "/etc/xdg/autostart/", "c:/programdata/microsoft/windows/start menu/programs/startup/",
];
const ASK_SYSTEM = ["/etc/profile", "/etc/bash.bashrc", "/etc/zshrc", "/etc/zsh/"];

export interface PersistHit { kind: "deny" | "ask"; label: string }

const SSH = "SSH access or startup file";
const STARTUP = "shell, PowerShell or git startup file";
const AUTOSTART = "autostart or scheduled-job location";
const SYSTEM = "system startup or scheduled-job location";

/** Where writing `np` would install persistence or change remote access, else null. */
export function persistenceHit(np: NormPath, ctx: PathCtx): PersistHit | null {
  const lower = trimEndChars((np.path ?? np.suffix ?? "").toLowerCase(), "/");
  if (lower === "") return null;
  const under = (base: string, d: string) => lower === `${base}/${d}` || lower.startsWith(`${base}/${d}/`);
  if (np.path !== null) {
    const home = (normalizeFull(ctx.homeDir, { ...ctx, cwd: "/" }) ?? "").toLowerCase();
    if (home) {
      for (const f of DENY_HOME_FILES) if (lower === `${home}/${f}`) return { kind: "deny", label: SSH };
      for (const d of DENY_HOME_DIRS) if (under(home, d)) return { kind: "deny", label: AUTOSTART };
      for (const f of ASK_HOME_FILES) if (lower === `${home}/${f}`) return { kind: "ask", label: STARTUP };
      for (const d of ASK_HOME_DIRS) if (under(home, d)) return { kind: "ask", label: STARTUP };
    }
    for (const s of DENY_SYSTEM) if (lower.startsWith(s) || lower === trimEndChars(s, "/")) return { kind: "deny", label: SYSTEM };
    for (const s of ASK_SYSTEM) if (lower.startsWith(s) || lower === trimEndChars(s, "/")) return { kind: "ask", label: STARTUP };
    return null;
  }
  // Only the suffix is known (e.g. $SOMEDIR/.bashrc): match on the file name.
  for (const f of DENY_HOME_FILES) if (lower.endsWith("/" + f)) return { kind: "deny", label: SSH };
  for (const d of DENY_HOME_DIRS) if (lower.includes("/" + d + "/") || lower.endsWith("/" + d)) return { kind: "deny", label: AUTOSTART };
  for (const f of ASK_HOME_FILES) if (lower.endsWith("/" + f)) return { kind: "ask", label: STARTUP };
  for (const d of ASK_HOME_DIRS) if (lower.includes("/" + d + "/") || lower.endsWith("/" + d)) return { kind: "ask", label: STARTUP };
  return null;
}

// Regenerable caches one level under home: deleting them is routine cleanup, not data loss.
const HOME_CACHES = new Set([".cache", ".npm", ".yarn", ".pnpm-store", ".node-gyp", ".gradle", ".m2", ".ivy2", ".bun", ".deno", ".nuget", ".pub-cache", ".expo", ".turbo"]);

/**
 * True when deleting `path` recursively would remove the home directory itself, everything in
 * it, or a whole folder one level under it (~/Documents, ~/Desktop, ~/.ssh, C:/Users/u/Pictures),
 * other than a regenerable cache. `path` is a normalized path; null is false.
 */
export function homeTopLevel(path: string | null, ctx: PathCtx): boolean {
  if (path === null) return false;
  const home = (normalizeFull(ctx.homeDir, { ...ctx, cwd: "/" }) ?? "").toLowerCase();
  if (home === "") return false;
  const lp = trimEndChars(path.toLowerCase(), "/");
  if (lp === home || lp === home + "/*") return true;
  if (!lp.startsWith(home + "/")) return false;
  const rest = lp.slice(home.length + 1);
  if (rest.includes("/")) return false;
  return rest !== "*" && !HOME_CACHES.has(rest);
}

/** Returns a label if `np` is a sensitive path, else null. */
export function sensitiveLabel(np: NormPath, ctx: PathCtx): string | null {
  const p = np.path ?? np.suffix ?? "";
  const lower = p.toLowerCase();
  const home = (normalizeFull(ctx.homeDir, { ...ctx, cwd: "/" }) ?? "").toLowerCase();
  if (np.path !== null && home) {
    for (const [d, label] of HOME_DIRS) if (lower === `${home}/${d}` || lower.startsWith(`${home}/${d}/`)) return label;
    for (const [f, label] of HOME_FILES) if (lower === `${home}/${f}`) return label;
  }
  const base = (lower.split("/").pop() ?? "");
  if (base === ".env" || (base.startsWith(".env.") && !/\.(example|sample|template|dist|defaults?)$/.test(base))) return "env-file";
  if (base.endsWith(".pem") || base.endsWith(".key") || base.endsWith(".p12") || base.endsWith(".pfx")) return "private-key";
  if (base.startsWith("id_rsa") || base.startsWith("id_ed25519") || base.startsWith("id_ecdsa") || base.startsWith("id_dsa")) return "ssh-private-key";
  if (lower === "/etc/shadow" || lower === "/etc/sudoers") return "system-credentials";
  for (const x of ctx.extraSensitive) {
    const n = normalizeFull(x.endsWith("/**") ? x.slice(0, -3) : x, { ...ctx, cwd: "/" });
    if (n && np.path !== null && (np.path === n || np.path.startsWith(n + "/"))) return "user-sensitive";
  }
  return null;
}

export function pathCtxFrom(c: {
  platform: PathCtx["platform"]; homeDir: string; cwd: string | null; caseInsensitiveFs: boolean; glassboxDirs: readonly string[];
  claudeConfigDir?: string | undefined; glassboxSecretPaths?: readonly string[] | undefined; resolvedPaths?: Readonly<Record<string, string>> | undefined;
  policy?: { extraProtectedPaths?: readonly string[] | undefined; extraSensitivePaths?: readonly string[] | undefined } | undefined;
}): PathCtx {
  return {
    platform: c.platform,
    homeDir: c.homeDir,
    cwd: c.cwd,
    caseInsensitive: c.caseInsensitiveFs,
    glassboxDirs: c.glassboxDirs,
    claudeConfigDir: c.claudeConfigDir,
    extraProtected: c.policy?.extraProtectedPaths ?? [],
    extraSensitive: c.policy?.extraSensitivePaths ?? [],
    secretPaths: c.glassboxSecretPaths ?? [],
    resolved: c.resolvedPaths,
  };
}
