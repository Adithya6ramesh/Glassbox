// Shell classification over the parsed AST.
import { Acc } from "../acc.js";
import { allLoopback, classifyUpload, recordUpload } from "../upload.js";
import { commandFiles, isRunKey, schtasksJob } from "../schedule.js";
import { trimEndChars } from "../../util/misc.js";
import { analyzeInlineCode } from "../inline.js";
import {
  coversProtectedRead, homeTopLevel, isProtected, isProtectedRead, normalizePath, persistenceHit, sensitiveLabel, suffixOnly, type NormPath, type PathCtx,
} from "../paths.js";
import { analyzeSql } from "../sql.js";
import { isProtectedWrite } from "../protected-write.js";
import { agentCliCommand, agentCliFor, agentConfigWrite, agentPackageBin } from "../agent-clis.js";
import { parseShell, Unanalyzable, type Redirect, type Script, type SimpleCommand, type Word } from "./parse.js";

export interface ShellState {
  pctx: PathCtx;
  depth: number; // substitution / bash -c recursion depth
  maxBytes: number;
}

// ── Word evaluation ──────────────────────────────────────────────────────

export interface WordInfo {
  word: Word;
  /** Fully literal value (quotes removed), or null if anything is dynamic. Globs keep their text. */
  value: string | null;
  /** Value for path checks: $HOME/~ kept for the normalizer; null if other dynamic parts. */
  pathValue: string | null;
  /** Literal text after the last dynamic part, if any. */
  suffix: string;
  dynamic: boolean;
  glob: boolean;
  substs: Script[];
}

export function wordInfo(w: Word): WordInfo {
  let value = "";
  let pathValue: string | null = "";
  let dynamic = false;
  let glob = false;
  let suffix = "";
  const substs: Script[] = [];
  for (const p of w.parts) {
    switch (p.t) {
      case "lit":
        value += p.s;
        if (pathValue !== null) pathValue += p.s;
        suffix += p.s;
        break;
      case "glob":
        glob = true;
        value += p.s;
        if (pathValue !== null) pathValue += p.s;
        suffix += p.s;
        break;
      case "tilde":
        dynamic = true;
        if (pathValue !== null) pathValue += "~" + p.user;
        suffix = "";
        break;
      case "var":
        dynamic = true;
        if (pathValue !== null && (p.name === "HOME" || (p.braced && p.name === "HOME"))) pathValue += "$HOME";
        else pathValue = null;
        suffix = "";
        break;
      case "subst":
        dynamic = true;
        substs.push(p.script);
        pathValue = null;
        suffix = "";
        break;
      case "arith":
        dynamic = true;
        pathValue = null;
        suffix = "";
        break;
    }
  }
  if (w.brace) dynamic = true;
  return { word: w, value: dynamic ? null : value, pathValue: w.brace ? null : pathValue, suffix, dynamic, glob, substs };
}

const isOption = (s: string | null) => s !== null && s.startsWith("-") && s !== "-";

function looksLikePath(s: string): boolean {
  return s.includes("/") || s.includes("\\") || s.startsWith("~") || s.startsWith(".") || s.startsWith("$HOME") || /^[a-zA-Z]:[\\/]/.test(s.slice(0, 3));
}

function npOf(w: WordInfo, pctx: PathCtx): NormPath | null {
  if (w.pathValue !== null) return normalizePath(w.pathValue, pctx);
  if (w.suffix.includes("/") || w.suffix.includes("\\")) return suffixOnly(w.suffix, pctx);
  if (w.suffix.length > 0) return suffixOnly("/" + w.suffix, pctx);
  return null; // fully unknown
}

// ── Tables ───────────────────────────────────────────────────────────────

const READ = new Set([
  "ls", "ll", "dir", "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "ack", "wc", "sort", "uniq", "diff", "cmp", "comm",
  "file", "stat", "pwd", "which", "whereis", "type", "echo", "printf", "date", "whoami", "id", "hostname", "uname", "tree", "jq", "yq", "cut", "tr",
  "column", "basename", "dirname", "realpath", "readlink", "du", "df", "printenv", "true", "false", "test", "[", "[[", "seq", "nl", "od", "xxd",
  "hexdump", "strings", "md5sum", "sha1sum", "sha256sum", "sha512sum", "shasum", "base64", "fold", "fmt", "rev", "tac", "paste", "join", "expand",
  "unexpand", "look", "man", "help", "ps", "top", "htop", "lsof", "uptime", "free", "nproc", "arch", "locale", "tput", "sleep", "wait", "cd", "pushd",
  "popd", "dirs", "export", "unset", "unalias", "local", "declare", "typeset", "readonly", "shift", "getopts", "read", "history", "jobs", "fg", "bg",
  "hash", "umask", "ulimit", "set", "shopt", "exit", "return", "break", "continue", ":", "time", "clear", "cal", "bc", "expr", "awk", "gawk", "sed",
  "tee_read_only", "zcat", "zgrep", "bzcat", "xzcat", "gzip_list", "printf", "getconf", "tty", "stty", "groups", "last", "w", "who", "env",
]);
const WRITE = new Set(["cp", "mkdir", "touch", "tee", "mv", "ln", "install", "patch", "mktemp", "unzip", "gunzip", "gzip", "bzip2", "xz", "zip", "tar", "dos2unix", "unix2dos", "split", "csplit", "rename"]);
const REMOVE = new Set(["rm", "rmdir", "unlink", "shred", "truncate", "srm"]);
const NET = new Set(["curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "ftp", "telnet", "ping", "dig", "nslookup", "host", "traceroute", "http", "https", "aria2c", "rsync_remote", "mosh"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "mksh"]);
const INTERPRETERS = new Set(["python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun", "Rscript", "osascript", "lua", "tclsh", "pwsh_inline"]);
const PROJECT = new Set(["make", "gmake", "cmake", "ninja", "pytest", "jest", "vitest", "mocha", "tsc", "eslint", "prettier", "biome", "mvn", "gradle", "gradlew", "dotnet", "rake", "tox", "nox", "ctest", "meson", "bazel", "turbo", "nx", "lerna", "playwright", "cypress", "webpack", "vite", "rollup", "esbuild", "swc", "babel", "ts-node", "tsx", "black", "ruff", "mypy", "flake8", "isort", "rubocop", "golangci-lint", "clippy", "rustfmt", "gofmt", "shellcheck", "hadolint", "phpunit", "pre-commit_run"]);
const HIJACK = new Set(["PATH", "BASH_ENV", "ENV", "PROMPT_COMMAND", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "NODE_OPTIONS", "NODE_PATH", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "IFS", "CDPATH", "GLOBIGNORE", "SHELLOPTS", "BASHOPTS", "PS4", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_ASKPASS", "GIT_EDITOR", "GIT_PAGER", "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_TEMPLATE_DIR", "EDITOR", "VISUAL", "PAGER", "SSH_ASKPASS", "SUDO_ASKPASS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "DOTNET_STARTUP_HOOKS"]);

const DANGEROUS_GIT_CONFIG = /^(alias\..*|core\.hookspath|core\.sshcommand|core\.pager|core\.editor|core\.fsmonitor|core\.gitproxy|credential\..*|diff\..*\.(textconv|command)|diff\.external|filter\..*|merge\..*\.driver|gpg\.program|sequence\.editor|uploadpack\..*|receivepack\..*)$/i;

// ── Analysis ─────────────────────────────────────────────────────────────

export function analyzeShellCommand(src: string, st: ShellState): Acc {
  const acc = new Acc();
  let script: Script;
  try {
    script = parseShell(src, { maxBytes: st.maxBytes });
  } catch (e) {
    acc.unanalyzable(e instanceof Unanalyzable ? e.reason : "parse error");
    // Even unparseable commands get the cheap protected-path scan.
    lexicalProtectedScan(src, st.pctx, acc);
    return acc;
  }
  analyzeScript(script, st, acc);
  return acc;
}

/** For commands we couldn't parse: look for protected-read/protected paths as plain text. */
function lexicalProtectedScan(src: string, pctx: PathCtx, acc: Acc): void {
  for (const tok of src.split(/[\s'"`;|&()<>=]+/).slice(0, 2000)) {
    if (!tok || !looksLikePath(tok)) continue;
    const np = normalizePath(tok, pctx);
    if (isProtectedRead(np, pctx)) acc.protect("CP-SELF-002", "reads a Glassbox credential file");
    else if (isProtected(np, pctx)) acc.protect("CP-SELF-001", "touches an agent or Glassbox control file");
  }
}

export function analyzeScript(script: Script, st: ShellState, acc: Acc): void {
  const cwdStack = { cwd: st.pctx.cwd };
  for (const cmd of script.commands) analyzeSimple(cmd, st, acc, cwdStack, script.functions);
  if (acc.network && acc.sensitiveArgs) acc.find("CP-EXFIL-030", "sensitive file and network call in one command");
  else if (acc.network && acc.envDump) acc.find("CP-EXFIL-030", "environment variables and a network call in one command");
  if (acc.newRemotes.length > 0 && acc.pushedTo.some((r) => acc.newRemotes.includes(r) || r === "\u0000dynamic" || acc.newRemotes.includes("\u0000dynamic"))) {
    acc.find("CP-EXFIL-034", "adds or repoints a git remote and pushes to it in the same command");
  }
}

function analyzeSubsts(w: WordInfo, st: ShellState, acc: Acc, commandPosition: boolean): void {
  for (const s of w.substs) {
    if (st.depth + 1 > 3) { acc.unanalyzable("command substitution nested more than 3 levels"); continue; }
    const inner = new Acc();
    analyzeScript(s, { ...st, depth: st.depth + 1 }, inner);
    if (inner.selfProtection) {
      acc.selfProtection = true;
      acc.tags.add("self-protection");
      for (const f of inner.findings) if (f.ruleId.startsWith("CP-SELF")) acc.find(f.ruleId, f.note);
      acc.raise("high-risk");
    }
    if (inner.sensitive.length > 0) { acc.sensitive.push(...inner.sensitive); acc.sensitiveArgs = true; }
    if (inner.envDump) acc.envDump = true;
    if (commandPosition) { acc.unanalyzable("command name comes from a command substitution"); continue; }
    if (inner.unanalyzableFlag) { acc.unanalyzable("command substitution contains an unanalyzable command"); continue; }
    const unknown = inner.tags.has("exec.unknown") || inner.tags.has("exec.project-code") || inner.tags.has("exec.inline-code") || inner.tags.has("exec.nested-agent");
    if (inner.level === "high-risk" || inner.sensitive.length > 0) {
      for (const t of inner.tags) acc.tags.add(t);
      acc.network ||= inner.network;
      acc.unanalyzable("command substitution runs a dangerous command");
      continue;
    }
    if (unknown) { acc.unanalyzable("command substitution runs an unknown command"); continue; }
    if (inner.level === "write-reversible") { acc.raise("write-reversible"); for (const t of inner.tags) acc.tags.add(t); }
  }
}

function analyzeSimple(cmd: SimpleCommand, st: ShellState, acc: Acc, cwd: { cwd: string | null }, functions: string[]): void {
  const pctx: PathCtx = { ...st.pctx, cwd: cwd.cwd };
  const envPrefix: string[] = [];
  for (const a of cmd.assigns) {
    const name = a.name;
    envPrefix.push(name);
    if (HIJACK.has(name) || name.startsWith("DYLD_") || name.startsWith("LD_")) acc.unanalyzable(`assignment to ${name} changes what later commands run`);
    if (a.value) {
      const wi = wordInfo(a.value);
      analyzeSubsts(wi, st, acc, false);
    }
  }
  const words = cmd.words.map(wordInfo);
  for (const r of cmd.redirects) handleRedirect(r, st, acc, pctx, cmd);
  if (words.length === 0) return;
  words.forEach((w, i) => analyzeSubsts(w, st, acc, i === 0));
  const head = words[0] as WordInfo;
  if (head.value === null || head.glob) {
    acc.unanalyzable("command name isn't a literal word");
    // Still check arguments for protected paths.
    for (const w of words.slice(1)) checkArgPaths(w, pctx, acc, false);
    return;
  }
  classify(head.value, words.slice(1), cmd, st, acc, pctx, cwd, envPrefix, functions, 0);
}

function handleRedirect(r: Redirect, st: ShellState, acc: Acc, pctx: PathCtx, cmd: SimpleCommand): void {
  if (r.heredoc) {
    if (r.heredoc.script) {
      const inner = new Acc();
      analyzeScript(r.heredoc.script, { ...st, depth: st.depth + 1 }, inner);
      // Substitutions in an unquoted here-doc body follow the same rules (Q5).
      const fake: WordInfo = { word: { parts: [], raw: "", brace: false }, value: null, pathValue: null, suffix: "", dynamic: true, glob: false, substs: [r.heredoc.script] };
      analyzeSubsts(fake, st, acc, false);
    }
    return;
  }
  if (!r.target) return;
  const t = wordInfo(r.target);
  analyzeSubsts(t, st, acc, false);
  const isWrite = r.op.startsWith(">") || r.op.startsWith("&>") || r.op === "<>";
  const val = t.pathValue ?? "";
  if (/^\/dev\/(tcp|udp)\//.test(val) || /^\/dev\/(tcp|udp)\//.test(t.suffix)) {
    acc.tag("high-risk", "net.egress");
    acc.network = true;
    acc.find("CP-SHELL-011");
    acc.reason("redirects to a network socket via /dev/tcp");
    return;
  }
  if (val === "/dev/null" || val === "/dev/stdout" || val === "/dev/stderr" || val === "&1" || val === "&2") return;
  if (r.op === "<<<") return;
  const np = npOf(t, pctx);
  if (isWrite) {
    if (np === null) { acc.unanalyzable("writes to a path that isn't known statically"); return; }
    if (/^\/dev\/(sd|nvme|hd|disk|xvd|vd|mmcblk)/.test(np.path ?? "")) { destroy(acc, "overwrites a disk device"); return; }
    if (np.path === "/proc/sysrq-trigger") { acc.tag("high-risk", "infra.change"); acc.reason("triggers a kernel reboot, power-off or crash through sysrq"); return; }
    if ((r.op === ">" || r.op === ">|") && np.path !== null && isLogOrHistory(np.path)) {
      acc.tag("high-risk", "fs.delete");
      acc.find("CP-ACTION-030", "empties a log or shell history file");
    }
    writeTarget(np, acc, pctx);
    acc.tag("write-reversible", "fs.write");
    return;
  }
  if (np) readTarget(np, acc, pctx, false);
  void cmd;
}

function destroy(acc: Acc, why: string): void {
  acc.tag("high-risk", "fs.destroy", "fs.delete");
  acc.find("CP-ACTION-001", why);
  acc.reason(why);
}

/** Checks for a path that is written, created, moved, deleted, chmod-ed or linked. */
function writeTarget(np: NormPath, acc: Acc, pctx: PathCtx, isGlob = false): void {
  if (isProtectedWrite(np, pctx, isGlob)) acc.protect("CP-SELF-001", "changes a file that controls the agent or Glassbox");
  acc.persist(persistenceHit(np, pctx), "changes", np.path);
  acc.wrote(np.path);
  agentConfigWrite(np, pctx, acc);
  const p = (np.path ?? np.suffix ?? "").toLowerCase();
  const home = trimEndChars(pctx.homeDir.replace(/\\/g, "/"), "/").toLowerCase();
  const homeFiles = [".bashrc", ".zshrc", ".profile", ".bash_profile", ".bash_login", ".zprofile", ".zshenv", ".zlogin", ".config/fish/config.fish", ".ssh/rc", ".inputrc"];
  const deferred =
    p.includes("/.git/hooks/") || p.endsWith("/.git/config") || p.includes("/.husky/") || p.endsWith("/.pre-commit-config.yaml") || p.endsWith("/.envrc") ||
    p.includes("/.config/systemd/user/") || p.includes("/library/launchagents/") || p.endsWith("microsoft.powershell_profile.ps1") || p.endsWith("profile.ps1") ||
    homeFiles.some((f) => p === `${home}/${f}` || (np.path === null && p.endsWith("/" + f) && f.startsWith(".")));
  if (deferred) { acc.tag("high-risk", "config.agent"); acc.reason("writes a file that runs commands later"); }
  if (p.endsWith("/.ssh/authorized_keys") || p.endsWith("/.ssh/authorized_keys2")) { acc.tag("high-risk", "perm.change"); acc.reason("changes SSH access"); }
}

function readTarget(np: NormPath, acc: Acc, pctx: PathCtx, recursive: boolean): void {
  if (recursive ? coversProtectedRead(np, pctx) : isProtectedRead(np, pctx)) { acc.protect("CP-SELF-002", "reads a Glassbox credential file"); return; }
  const label = sensitiveLabel(np, pctx);
  if (label) {
    acc.tags.add("fs.read.sensitive");
    acc.sensitive.push(label);
    acc.sensitiveArgs = true;
    acc.find("CP-EXFIL-040", label);
    acc.reason(`reads a sensitive file (${label})`);
  }
}

/** Every path-like argument of any command: protected reads and sensitive reads. */
function checkArgPaths(w: WordInfo, pctx: PathCtx, acc: Acc, recursive: boolean, writeOnly = false): void {
  const text = w.pathValue ?? w.suffix;
  if (!text) return;
  // `--opt=path` and `@path` forms.
  const candidates = [text];
  const eq = text.indexOf("=");
  if (eq > 0 && text.startsWith("-")) candidates.push(text.slice(eq + 1));
  if (text.startsWith("@")) candidates.push(text.slice(1));
  for (const c of candidates) {
    if (!looksLikePath(c) && !c.startsWith(".env") && !c.endsWith(".key") && !c.endsWith(".pem")) continue;
    const np = w.pathValue !== null ? normalizePath(c, pctx) : suffixOnly(c, pctx);
    if (writeOnly) { if (isProtectedRead(np, pctx)) acc.protect("CP-SELF-001", "changes a Glassbox credential file"); continue; }
    readTarget(np, acc, pctx, recursive);
  }
}

interface Ctx2 { cmd: SimpleCommand; st: ShellState; acc: Acc; pctx: PathCtx; cwd: { cwd: string | null }; envPrefix: string[]; functions: string[] }

function operands(args: WordInfo[], takesValue: Set<string> = new Set()): WordInfo[] {
  const out: WordInfo[] = [];
  let endOpts = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as WordInfo;
    const v = a.value;
    if (!endOpts && v === "--") { endOpts = true; continue; }
    if (!endOpts && isOption(v)) { if (v !== null && takesValue.has(v)) i++; continue; }
    out.push(a);
  }
  return out;
}

function hasFlag(args: WordInfo[], ...flags: string[]): boolean {
  return args.some((a) => {
    const v = a.value;
    if (v === null || !v.startsWith("-")) return false;
    if (flags.includes(v)) return true;
    // Combined short flags: -rf contains r and f.
    if (!v.startsWith("--")) return flags.some((f) => f.length === 2 && f.startsWith("-") && !f.startsWith("--") && v.slice(1).includes(f[1] as string));
    return flags.some((f) => f.startsWith("--") && v.startsWith(f + "="));
  });
}

function stdinKind(cmd: SimpleCommand): "pipe" | "heredoc" | "file" | "herestring" | "none" {
  if (cmd.pipedIn) return "pipe";
  for (const r of cmd.redirects) {
    if (r.heredoc) return "heredoc";
    if (r.op === "<<<") return "herestring";
    if (r.op === "<" || r.op === "<>") return "file";
  }
  return "none";
}

const NET_PIPE_SOURCES = new Set(["curl", "wget", "nc", "ncat", "fetch", "http", "https", "aria2c"]);

function classify(name0: string, args: WordInfo[], cmd: SimpleCommand, st: ShellState, acc: Acc, pctx: PathCtx, cwd: { cwd: string | null }, envPrefix: string[], functions: string[], unwrapDepth: number): void {
  const c: Ctx2 = { cmd, st, acc, pctx, cwd, envPrefix, functions };
  const name = name0.includes("/") && !name0.startsWith("./") && !name0.startsWith("../") ? (name0.split("/").pop() ?? name0) : name0;
  const lower = name.toLowerCase();

  // Every path-like argument: protected reads and sensitive reads. Destinations of
  // copy/move/create commands are writes, not reads.
  const writeOnly = new Set<WordInfo>();
  if (["cp", "mv", "ln", "install"].includes(lower)) { const o = operands(args); const last = o[o.length - 1]; if (last && o.length > 1) writeOnly.add(last); }
  if (["touch", "mkdir", "rm", "rmdir", "unlink", "shred", "truncate", "tee"].includes(lower)) for (const o of operands(args)) writeOnly.add(o);
  const recursiveRead = (["grep", "egrep", "fgrep", "rg", "ag", "ack"].includes(lower) && (hasFlag(args, "-r", "-R", "--recursive") || lower === "rg" || lower === "ag" || lower === "ack")) ||
    ["tar", "zip", "rsync", "find", "du", "tree", "scp", "7z"].includes(lower) || (lower === "cp" && hasFlag(args, "-r", "-R", "-a", "--recursive", "--archive")) || (lower === "ls" && hasFlag(args, "-R"));
  for (const a of args) checkArgPaths(a, pctx, acc, recursiveRead, writeOnly.has(a));

  // Version/help probes of any tool are reads.
  if (args.length === 1 && ["--version", "-v", "-V", "--help", "-h"].includes(args[0]?.value ?? "") && !["rm", "sudo", "doas", "bash", "sh", "claude", "env"].includes(lower)) return;

  if (functions.includes(name)) return; // body already analyzed

  // Whole-environment dumps (correlated with network calls in analyzeScript).
  const flagsOnly = (allowed: string[]) => args.every((a) => a.value !== null && allowed.includes(a.value));
  if ((lower === "printenv" && args.length === 0) || (["set", "export", "declare", "typeset"].includes(lower) && flagsOnly(["-p", "-x", "-px", "-xp"]))) acc.envDump = true;
  if (lower === "compgen" && hasFlag(args, "-e", "-v")) acc.envDump = true;

  // Credential dumping tools, run directly or as a script (python laZagne.py).
  if ([name, ...args.map((a) => a.value ?? "")].some((v) => /^(lazagne|mimikatz|pypykatz|secretsdump|procdump)/i.test(v.slice(v.lastIndexOf("/") + 1)))) {
    acc.tags.add("fs.read.sensitive");
    acc.raise("high-risk");
    acc.sensitive.push("credential-dump");
    acc.sensitiveArgs = true;
    acc.find("CP-EXFIL-040", "runs a credential dumping tool");
  }

  // Clearing shell history or system logs hides what happened (warn, CP-ACTION-030).
  const clearsHistory = (lower === "history" && args.some((a) => /^-[a-z]*c/.test(a.value ?? "") || a.value === "-d")) ||
    (lower === "unset" && args.some((a) => a.value === "HISTFILE")) ||
    (lower === "journalctl" && args.some((a) => (a.value ?? "").startsWith("--vacuum") || a.value === "--rotate"));
  if (clearsHistory) {
    acc.tag("high-risk", "fs.delete");
    acc.find("CP-ACTION-030", `${lower} clears shell history or system logs`);
    acc.reason("clears shell history or logs");
    return;
  }

  // DNS lookups of a name built from command output or variables: data smuggled out in DNS.
  if (["nslookup", "dig", "host", "drill", "ping", "ping6", "resolvectl", "getent"].includes(lower)) {
    if (operands(args).some((a) => a.substs.length > 0 || a.value === null)) {
      acc.tag("high-risk", "net.egress");
      acc.network = true;
      acc.find("CP-EXFIL-033", `${lower} looks up a name built from command output or variables`);
    }
  }

  // ── Wrappers ───────────────────────────────────────────────────────────
  const unwrap = (rest: WordInfo[]) => {
    if (unwrapDepth >= 4) { acc.unanalyzable("too many nested wrapper commands"); return; }
    const h = rest[0];
    if (!h) return;
    if (h.value === null || h.glob) { acc.unanalyzable("wrapped command name isn't literal"); return; }
    classify(h.value, rest.slice(1), cmd, st, acc, pctx, cwd, envPrefix, functions, unwrapDepth + 1);
  };
  const skipOpts = (rest: WordInfo[], withValue: Set<string>): WordInfo[] => {
    let i = 0;
    while (i < rest.length) {
      const v = rest[i]?.value ?? null;
      if (v === "--") { i++; break; }
      if (!isOption(v)) break;
      i += withValue.has(v as string) ? 2 : 1;
    }
    return rest.slice(i);
  };
  switch (lower) {
    case "sudo": case "doas": case "su": {
      acc.tag("high-risk", "perm.change");
      acc.reason("runs with elevated privileges");
      if (lower === "su") { if (hasFlag(args, "-c")) acc.unanalyzable("su -c runs a command string"); return; }
      return unwrap(skipOpts(args, new Set(["-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "--user", "--group"])));
    }
    case "env": {
      let i = 0;
      while (i < args.length) {
        const v = args[i]?.value ?? null;
        if (v === "-i" || v === "--ignore-environment" || v === "-0" || v === "--null") { i++; continue; }
        if (v === "-u" || v === "--unset" || v === "-C" || v === "--chdir" || v === "-S") { if (v === "-S") acc.unanalyzable("env -S splits a command string"); i += 2; continue; }
        if (v !== null && /^[A-Za-z_][A-Za-z0-9_]*=/.test(v)) {
          const varName = v.split("=")[0] as string;
          envPrefix.push(varName);
          if (HIJACK.has(varName) || varName.startsWith("DYLD_") || varName.startsWith("LD_")) acc.unanalyzable(`env sets ${varName}, which changes what runs`);
          i++;
          continue;
        }
        if (args[i]?.value === null) { acc.unanalyzable("env argument isn't literal"); return; }
        break;
      }
      const rest = args.slice(i);
      if (rest.length === 0) { acc.envDump = true; return; } // prints the environment
      return unwrap(rest);
    }
    case "command": case "builtin": {
      if (hasFlag(args, "-v", "-V")) return;
      return unwrap(skipOpts(args, new Set()));
    }
    case "exec": {
      if (args.length === 0) return;
      return unwrap(skipOpts(args, new Set(["-a"])));
    }
    case "nohup": case "time": case "caffeinate": return unwrap(skipOpts(args, new Set()));
    case "nice": return unwrap(skipOpts(args, new Set(["-n", "--adjustment"])));
    case "ionice": return unwrap(skipOpts(args, new Set(["-c", "-n", "-p", "-t"])));
    case "stdbuf": return unwrap(skipOpts(args, new Set(["-i", "-o", "-e"])));
    case "chrt": case "taskset": return unwrap(skipOpts(args, new Set()).slice(1));
    case "timeout": case "gtimeout": {
      const rest = skipOpts(args, new Set(["-s", "--signal", "-k", "--kill-after"]));
      return unwrap(rest.slice(1));
    }
    case "watch": return unwrap(skipOpts(args, new Set(["-n", "--interval", "-d"])));
    case "xargs": {
      const rest = skipOpts(args, new Set(["-n", "-L", "-P", "-I", "-i", "-d", "-E", "-s", "-a", "--max-args", "--max-procs", "--delimiter", "--replace", "--arg-file"]));
      if (rest.length === 0) return;
      // The arguments xargs adds come from stdin, so they're unknown (red team, Step 5).
      const unknownArg: WordInfo = { word: { parts: [{ t: "var", name: "XARGS", braced: false, quoted: false }], raw: "<stdin>", brace: false }, value: null, pathValue: null, suffix: "", dynamic: true, glob: false, substs: [] };
      return unwrap([...rest, unknownArg]);
    }
    case "parallel": return unwrap(skipOpts(args, new Set(["-j", "--jobs"])));
    case "npx": case "bunx": case "pnpx": {
      acc.tags.add("net.fetch.package-manager");
      const rest = skipOpts(args, new Set(["-p", "--package", "-c"]));
      if (hasFlag(args, "-c")) { acc.unanalyzable("npx -c runs a command string"); return; }
      if (rest.length === 0) return;
      return projectTool(rest, c, unwrapDepth);
    }
  }

  // ── Self-protection commands ───────────────────────────────────────────
  if (lower === "glassbox" || lower === "glassbox.exe") { glassboxCli(args, acc); return; }
  if (lower === "claude" || lower === "claude.exe") return claudeCommand(args, c);
  // Other agent CLIs (rev 11, §7.10): nested agents; approval/sandbox-off flags are denied.
  const agentCli = agentCliFor(lower);
  if (agentCli) return agentCliCommand(agentCli, args.map((a) => a.value), envOf(c.cmd), acc);
  if (lower === "reg" || lower === "reg.exe") {
    const flat = args.map((a) => (a.value ?? a.word.raw)).join(" ").toLowerCase().replace(/[\\/"']/g, "");
    if (flat.includes("policiesclaudecode")) { acc.protect("CP-SELF-003", "changes Claude Code policy in the registry"); return; }
    const sub = (args[0]?.value ?? "").toLowerCase();
    if (["add", "delete", "import", "restore", "load", "copy"].includes(sub)) {
      acc.tag("high-risk", "config.agent");
      // Run / RunOnce keys start programs at every login (rev 11): a scheduled job (CP-SELF-006).
      if (isRunKey(flat)) acc.scheduleJob({ kind: "autostart", verb: sub === "delete" ? "removes" : "changes", path: null, schedule: "at login (registry Run key)", files: [] });
      // import/restore/load take a file whose keys aren't visible: they may write a Run key.
      if (["import", "restore", "load"].includes(sub)) acc.reason("loads registry keys from a file");
    }
    return;
  }

  // ── Shells and interpreters ────────────────────────────────────────────
  if (SHELLS.has(lower)) return shellInvocation(args, c, unwrapDepth);
  if (lower === "cmd" || lower === "cmd.exe") { acc.unanalyzable("cmd.exe syntax isn't analyzed"); return; }
  if (lower === "powershell" || lower === "pwsh" || lower === "powershell.exe" || lower === "pwsh.exe") { acc.unanalyzable("PowerShell started from a shell command"); return; }
  if (INTERPRETERS.has(lower) || /^python\d(\.\d+)?$/.test(lower)) return interpreter(lower, args, c);
  if (lower === "eval" || lower === "source" || lower === "." || lower === "alias" || lower === "trap" || lower === "enable" || lower === "coproc") {
    acc.unanalyzable(`'${lower}' runs code that can't be analyzed statically`);
    return;
  }
  if (lower === "set") {
    if (args.some((a) => /^[-+][a-zA-Z]*[fB]/.test(a.value ?? "") || /^(noglob|braceexpand)$/.test(a.value ?? ""))) acc.unanalyzable("set changes how later words expand");
    return;
  }
  if (lower === "shopt") {
    if (args.some((a) => ["expand_aliases", "extglob", "nullglob", "failglob", "dotglob"].includes(a.value ?? "") ) && hasFlag(args, "-s")) acc.unanalyzable("shopt changes how later commands expand");
    return;
  }
  if (lower === "export" || lower === "declare" || lower === "typeset" || lower === "local" || lower === "readonly") {
    for (const a of args) {
      const v = a.value ?? a.word.raw;
      const nm = v.split("=")[0] ?? "";
      if (HIJACK.has(nm) || nm.startsWith("DYLD_") || nm.startsWith("LD_")) acc.unanalyzable(`${lower} ${nm} changes what later commands run`);
      if (v.startsWith("-f") || v === "-f") acc.unanalyzable(`${lower} -f exports functions`);
    }
    return;
  }
  if (lower === "cd" || lower === "pushd" || lower === "popd") {
    const target = args.find((a) => !isOption(a.value));
    if (lower === "popd" || (target && target.value === "-")) { cwd.cwd = null; return; }
    if (!target) { cwd.cwd = pctx.homeDir; return; }
    if (target.pathValue === null) { cwd.cwd = null; return; }
    const np = normalizePath(target.pathValue, pctx);
    cwd.cwd = np.path;
    return;
  }

  // ── Version control ────────────────────────────────────────────────────
  if (lower === "git") return git(args, c);
  if (lower === "gh") return gh(args, c);

  // ── Package managers and project tools ─────────────────────────────────
  if (["npm", "pnpm", "yarn", "bun"].includes(lower)) return jsPm(lower, args, c);
  if (["pip", "pip3", "pipx", "uv", "poetry", "pdm", "conda", "mamba", "cargo", "go", "gem", "bundle", "bundler", "composer", "apt", "apt-get", "brew", "yum", "dnf", "pacman", "apk", "choco", "winget", "scoop", "dotnet", "mvn", "gradle", "deno"].includes(lower)) return otherPm(lower, args, c);
  if (name.startsWith("./") || name.startsWith("../") || PROJECT.has(lower) || lower === "gradlew") { acc.tag("write-reversible", "exec.project-code"); return; }

  // ── Database CLIs ──────────────────────────────────────────────────────
  if (["psql", "mysql", "sqlite3", "mariadb", "sqlcmd", "duckdb", "clickhouse-client"].includes(lower)) return dbCli(lower, args, c);

  // ── Classes from the command table ─────────────────────────────────────
  if (lower === "redis-cli" || lower === "valkey-cli" || lower === "keydb-cli") {
    if (args.some((a) => ["flushall", "flushdb"].includes((a.value ?? "").toLowerCase()))) {
      acc.tag("high-risk", "db.unscoped-write", "db.delete");
      acc.reason("deletes every key in the Redis database");
      return;
    }
  }
  if (REMOVE.has(lower)) return remove(lower, args, c);
  if (lower === "find") return find(args, c, unwrapDepth);
  if (lower === "dd") {
    acc.tag("write-reversible", "fs.write");
    for (const a of args) {
      const v = a.value ?? "";
      if (v.startsWith("of=")) {
        const target = v.slice(3);
        if (/^\/dev\/(sd|nvme|hd|disk|xvd|vd|mmcblk|rdisk)/.test(target)) destroy(acc, "overwrites a disk device");
        else writeTarget(normalizePath(target, pctx), acc, pctx);
      }
      if (a.value === null && (a.word.raw.startsWith("of="))) acc.unanalyzable("dd output isn't known statically");
    }
    return;
  }
  if (lower.startsWith("mkfs") || lower === "diskpart" || lower === "fdisk" || lower === "parted" || lower === "wipefs" || lower === "format") { destroy(acc, "formats or repartitions a disk"); return; }
  if (["chmod", "chown", "chgrp", "setfacl", "chattr", "icacls", "takeown", "attrib", "passwd", "usermod", "useradd", "visudo", "setcap"].includes(lower)) return perm(lower, args, c);
  if (lower === "crontab") {
    // Listing is a read; installing, editing or removing a crontab is a scheduled job (CP-SELF-006).
    const flags = args.map((a) => a.value ?? "");
    if (flags.every((f) => f === "-l" || f === "-u" || !f.startsWith("-")) && flags.includes("-l")) return;
    if (flags.includes("-r")) { acc.scheduleJob({ kind: "cron", verb: "removes", path: null, schedule: "every job in this crontab", files: [] }); return; }
    const file = operands(args, new Set(["-u"]))[0];
    const fileVal = file && file.value !== "-" ? file.pathValue : null;
    const np = fileVal ? normalizePath(fileVal, pctx) : null;
    // The schedule comes from the crontab text when it's in the command (echo … | crontab -).
    acc.scheduleJob({ kind: "cron", verb: flags.includes("-e") ? "changes" : "creates", path: null, schedule: null, files: np?.path ? [np.path] : [] });
    return;
  }
  if (lower === "rsync") return rsync(args, c);
  if (NET.has(lower)) return network(lower, args, c);
  if (["docker", "podman"].includes(lower)) return docker(args, c);
  if (["kubectl", "helm", "terraform", "tofu", "pulumi", "vercel", "netlify", "fly", "flyctl", "wrangler", "firebase", "heroku", "aws", "gcloud", "gsutil", "az", "doctl", "serverless", "sls", "cdk", "eb", "railway", "render"].includes(lower)) return deploy(lower, args, c);
  if (["twine", "gem_push"].includes(lower)) { acc.tag("high-risk", "publish.public", "net.egress"); acc.network = true; return; }
  if (lower === "sed") {
    if (!hasFlag(args, "-i", "--in-place")) return;
    let ops = operands(args, new Set(["-e", "-f", "--expression", "--file"]));
    if (!hasFlag(args, "-e", "-f", "--expression", "--file")) ops = ops.slice(1);
    return writeOps(ops, c, "fs.write");
  }
  if (lower === "awk" || lower === "gawk") {
    if (args.some((a) => a.value === "inplace")) acc.tag("write-reversible", "fs.write");
    if (args.some((a) => (a.value ?? "").includes("system(") || (a.value ?? "").includes("| getline"))) acc.unanalyzable("awk program runs commands");
    return;
  }
  if (lower === "tee") return writeOps(operands(args), c, "fs.write");
  if (lower === "mv") return writeOps(operands(args, new Set(["-t", "--target-directory", "-S", "--suffix"])), c, "fs.move");
  if (lower === "ln") return writeOps(operands(args, new Set(["-t", "--target-directory", "-S", "--suffix"])), c, "fs.write");
  if (lower === "tar") {
    const create = args.some((a) => /^-?[a-z]*c/.test(a.value ?? "") && !(a.value ?? "").startsWith("--"));
    const extract = args.some((a) => /^-?[a-z]*x/.test(a.value ?? "") && !(a.value ?? "").startsWith("--"));
    if (extract || create) acc.tag("write-reversible", "fs.write");
    return;
  }
  if (WRITE.has(lower)) return writeOps(operands(args, new Set(["-t", "--target-directory", "-m", "--mode", "-S", "--suffix", "-o", "-g", "-p"])), c, "fs.write");
  if (READ.has(lower)) return;
  // Scheduled jobs and services (rev 9): ask with the schedule and the command (CP-SELF-006).
  if (scheduledJobCommand(lower, args, c)) return;
  if (["kill", "pkill", "killall", "systemctl", "service", "launchctl", "shutdown", "reboot", "halt", "poweroff", "init", "telinit"].includes(lower)) {
    const vals = args.map((a) => (a.value ?? "").toLowerCase());
    const power = ["shutdown", "reboot", "halt", "poweroff"].includes(lower) || ((lower === "init" || lower === "telinit") && ["0", "6"].includes(vals[0] ?? ""));
    const sysctlPower = lower === "systemctl" && vals.some((v) => ["poweroff", "reboot", "halt", "kexec", "suspend", "hibernate", "emergency", "rescue"].includes(v));
    const stopsService = (lower === "systemctl" && vals.some((v) => ["stop", "disable", "mask", "kill"].includes(v))) || (lower === "service" && vals.includes("stop"));
    if (power || sysctlPower) { acc.tag("high-risk", "infra.change"); acc.reason("powers off or restarts the machine"); }
    else if (stopsService) { acc.tag("high-risk", "infra.change"); acc.reason("stops or disables a system service"); }
    else acc.tag("write-reversible", "exec.unknown");
    return;
  }
  // Deleting backups, shadow copies or recovery settings: irreversible (ask).
  if ((lower === "vssadmin" && args.some((a) => /^(delete|resize)$/i.test(a.value ?? ""))) || lower === "diskshadow" ||
      (lower === "wbadmin" && args.some((a) => /^delete$/i.test(a.value ?? ""))) ||
      (lower === "wmic" && args.some((a) => /^shadowcopy$/i.test(a.value ?? "")) && args.some((a) => /^delete$/i.test(a.value ?? ""))) ||
      (lower === "bcdedit" && args.some((a) => /recoveryenabled|bootstatuspolicy/i.test(a.value ?? "")))) {
    acc.tag("high-risk", "fs.destroy");
    acc.reason("deletes backups, shadow copies or recovery settings");
    return;
  }
  acc.tag("write-reversible", "exec.unknown");
  acc.reason(`runs '${name.slice(0, 40)}', which Glassbox doesn't classify`);
  // Red team (Step 4): an unclassified program (an editor, a custom tool) handed a
  // protected path may write it. Known read-only commands are classified above and stay allowed.
  for (const a of args) {
    const v = a.pathValue;
    if (v === null || !looksLikePath(v)) continue;
    if (isProtectedWrite(normalizePath(v, pctx), pctx, a.glob)) { acc.protect("CP-SELF-001", "hands a protected agent or Glassbox file to a program that may change it"); return; }
  }
}

/** Environment variables set for this command (`VAR=value cmd`), with literal values (null = not literal). */
function envOf(cmd: SimpleCommand): Map<string, string | null> {
  const m = new Map<string, string | null>();
  for (const a of cmd.assigns) m.set(a.name, a.value ? wordInfo(a.value).value : "");
  return m;
}

function claudeCommand(args: WordInfo[], c: Ctx2): void {
  const { acc } = c;
  const vals = args.map((a) => a.value);
  if (c.envPrefix.some((e) => e === "CLAUDE_CONFIG_DIR" || e.startsWith("CLAUDE_CODE_"))) { acc.protect("CP-SELF-003", "starts a nested agent with a different configuration"); return; }
  const danger = ["--settings", "--setting-sources", "--plugin-dir", "--mcp-config", "--strict-mcp-config", "--dangerously-skip-permissions", "--allow-dangerously-skip-permissions"];
  if (vals.some((v) => v !== null && danger.some((d) => v === d || v.startsWith(d + "=")))) { acc.protect("CP-SELF-003", "starts a nested agent that overrides settings or permissions"); return; }
  const pm = vals.indexOf("--permission-mode");
  if (pm >= 0 && (vals[pm + 1] === "bypassPermissions" || vals[pm + 1] === null)) { acc.protect("CP-SELF-003", "starts a nested agent with permissions bypassed"); return; }
  if (vals.some((v) => v !== null && v.startsWith("--permission-mode=bypass"))) { acc.protect("CP-SELF-003", "starts a nested agent with permissions bypassed"); return; }
  if (vals[0] === "plugin" || vals[0] === "plugins") {
    if (["disable", "uninstall", "remove", "marketplace", "install", "enable"].includes(vals[1] ?? "")) { acc.protect("CP-SELF-003", "changes agent plugins"); return; }
    return;
  }
  if (vals[0] === "mcp" && ["add", "remove", "add-json", "add-from-claude-desktop", "reset-project-choices"].includes(vals[1] ?? "")) { acc.protect("CP-SELF-003", "changes the agent's MCP servers"); return; }
  if (vals[0] === "config" && ["set", "add", "remove"].includes(vals[1] ?? "")) { acc.protect("CP-SELF-003", "changes agent configuration"); return; }
  if (args.length === 1 && ["--version", "-v", "--help", "-h"].includes(vals[0] ?? "")) return;
  // An argument that isn't known statically could be --dangerously-skip-permissions (rev 11).
  if (vals.some((v) => v === null)) { acc.unanalyzable("claude with arguments that aren't known statically"); return; }
  acc.tag("high-risk", "exec.nested-agent");
  acc.reason("starts a nested agent");
}

function shellInvocation(args: WordInfo[], c: Ctx2, unwrapDepth: number): void {
  const { acc, cmd, st } = c;
  const ci = args.findIndex((a) => a.value === "-c" || (a.value !== null && /^-[a-z]*c$/.test(a.value)));
  if (ci >= 0) {
    const script = args[ci + 1];
    if (!script || script.value === null) { acc.unanalyzable("shell -c with a non-literal command string"); return; }
    if (st.depth + 1 > 3 || unwrapDepth >= 4) { acc.unanalyzable("shell -c nested too deep"); return; }
    const inner = analyzeShellCommand(script.value, { ...st, depth: st.depth + 1 });
    acc.merge(inner);
    return;
  }
  const kind = stdinKind(cmd);
  const fileArg = operands(args, new Set(["-o", "+o", "-O", "+O"]))[0];
  if (fileArg) {
    if (fileArg.value === null) { acc.unanalyzable("shell runs a script whose name isn't literal"); return; }
    acc.tag("write-reversible", "exec.project-code");
    return;
  }
  if (kind === "heredoc") {
    const h = cmd.redirects.find((r) => r.heredoc)?.heredoc;
    if (h) {
      if (st.depth + 1 > 3) { acc.unanalyzable("nested too deep"); return; }
      acc.merge(analyzeShellCommand(h.body, { ...st, depth: st.depth + 1 }));
      return;
    }
  }
  if (kind === "herestring") {
    const r = cmd.redirects.find((x) => x.op === "<<<");
    const v = r?.target ? wordInfo(r.target).value : null;
    if (v === null) { acc.unanalyzable("shell reads a non-literal here-string"); return; }
    acc.merge(analyzeShellCommand(v, { ...st, depth: st.depth + 1 }));
    return;
  }
  if (kind === "pipe") {
    const from = cmd.pipedFrom?.words[0];
    const fromName = from ? (wordInfo(from).value ?? "") : "";
    if (NET_PIPE_SOURCES.has(fromName.split("/").pop() ?? "")) { acc.find("CP-SHELL-010"); acc.tag("high-risk", "net.egress"); acc.network = true; }
    acc.unanalyzable("a shell reads commands from a pipe");
    return;
  }
  if (kind === "file") { acc.unanalyzable("a shell reads commands from a file redirect"); return; }
  acc.tag("write-reversible", "exec.unknown");
}

function interpreter(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc, cmd, pctx } = c;
  // Red team (Step 4): an interpreter can write any path it's handed (perl -pi -e …, a
  // script given ~/.claude/settings.json), and a here-doc or here-string body is inline code.
  for (const a of args) {
    const np = a.pathValue !== null && looksLikePath(a.pathValue) ? normalizePath(a.pathValue, pctx) : null;
    if (np && isProtectedWrite(np, pctx, a.glob)) { acc.protect("CP-SELF-001", "hands a protected agent or Glassbox file to an interpreter"); return; }
  }
  // An interpreter running the Glassbox CLI script directly (node …/glassbox/dist/cli.js allow …).
  const gbScript = args.findIndex((a) => a.value !== null && !a.value.startsWith("-") && a.value.toLowerCase().includes("glassbox"));
  if (gbScript >= 0) { glassboxCli(args.slice(gbScript + 1), acc); if (acc.selfProtection) return; }
  const hereStr = cmd.redirects.find((r) => r.op === "<<<")?.target;
  const body = cmd.redirects.find((r) => r.heredoc)?.heredoc?.body ?? (hereStr ? wordInfo(hereStr).value ?? "" : "");
  if (body && protectedText(body, pctx)) { acc.protect(body.includes(".key") ? "CP-SELF-002" : "CP-SELF-001", "inline code refers to a protected agent or Glassbox file"); return; }
  const flagsWithCode = new Set(["-c", "-e", "--eval", "-p", "--print", "-E", "-r"]);
  const idx = args.findIndex((a) => a.value !== null && (flagsWithCode.has(a.value) || (lower.startsWith("python") && /^-[A-Za-z]*c$/.test(a.value))));
  if (idx >= 0) {
    const code = args[idx + 1];
    acc.tag("write-reversible", "exec.inline-code");
    if (!code || code.value === null) { acc.unanalyzable("inline code isn't a literal string"); return; }
    // Protected paths inside the code → self-protection.
    if (protectedText(code.value, pctx)) {
      const lowerCode = code.value.toLowerCase();
      acc.protect(lowerCode.includes(".key") || lowerCode.includes("device") ? "CP-SELF-002" : "CP-SELF-001", "inline code refers to a protected agent or Glassbox file");
      return;
    }
    // Module flags (perl -MLWP::Simple, ruby -rnet/http) count as part of the code.
    const modules = args.filter((a) => a.value !== null && (/^-M./.test(a.value) || /^-r[a-z]/.test(a.value))).map((a) => (a.value as string).slice(2));
    const v = analyzeInlineCode(modules.length > 0 ? `${code.value} ${modules.join(" ")}` : code.value);
    if (v.unanalyzable) { acc.unanalyzable(v.unanalyzable); return; }
    // Spec rev 6, Q3: what the code is aimed at.
    if (v.network) { acc.tag("high-risk", "net.egress"); acc.network = true; }
    if (v.sensitive) { acc.sensitive.push("credentials or environment in inline code"); acc.sensitiveArgs = true; }
    // A tree delete aimed at home or the root destroys data (same bar as rm -rf ~); a tree
    // delete of a named folder like 'build' stays at the ordinary delete level.
    if (v.destroysTree && v.homeOrRoot) {
      acc.tag("high-risk", "fs.destroy");
      acc.find("CP-ACTION-001", "inline code deletes the home directory or the filesystem root");
    }
    if (v.dangerous) { acc.raise("high-risk"); acc.reason("inline code deletes files, uses the network or runs processes"); if (/\b(requests|urllib|http|fetch|socket|axios|httpx)\b/.test(code.value)) { acc.tags.add("net.egress"); acc.network = true; } else acc.tags.add("fs.delete"); }
    return;
  }
  if (args.some((a) => a.value === "-m")) { acc.tag("write-reversible", "exec.project-code"); return; }
  const file = operands(args, new Set(["-W", "-X", "--require", "-r", "--import", "--loader", "-I"]))[0];
  const kind = stdinKind(cmd);
  if (file && file.value !== "-") {
    if (file.value === null) { acc.unanalyzable("interpreter runs a script whose name isn't literal"); return; }
    acc.tag("write-reversible", "exec.project-code");
    return;
  }
  if (kind !== "none" || file?.value === "-") {
    if (kind === "pipe") {
      const from = cmd.pipedFrom?.words[0];
      const fromName = from ? (wordInfo(from).value ?? "") : "";
      if (NET_PIPE_SOURCES.has(fromName)) { acc.find("CP-SHELL-010"); acc.tag("high-risk", "net.egress"); acc.network = true; }
    }
    acc.unanalyzable("an interpreter reads code from stdin");
    return;
  }
  acc.tag("write-reversible", "exec.inline-code");
  acc.reason("starts an interactive interpreter");
}

/** Does free text (inline code, a here-doc) mention a protected agent or Glassbox path? */
function protectedText(text: string, pctx: PathCtx): boolean {
  const norm = (x: string) => x.toLowerCase().split("\\").join("/");
  const t = norm(text);
  const needles = [".glassbox", ".claude/settings", ".claude.json", ".mcp.json", ".claude/hooks", ".claude/plugins", "claudecode/", "policies/claudecode"];
  if (pctx.claudeConfigDir) needles.push(norm(pctx.claudeConfigDir) + "/settings");
  for (const sp of pctx.secretPaths) needles.push(norm(sp));
  return needles.some((n) => n.length > 0 && t.includes(n));
}

/**
 * The Glassbox CLI: subcommands that change protection are self-protection (the agent may
 * never run them, however it launches the CLI). A non-literal argument counts as changing.
 */
const GLASSBOX_MUTATING = new Set(["mode", "allow", "uninstall", "logout", "login", "install", "pair", "unpair", "config", "set", "disable", "enable", "reset", "deny", "forget", "revoke"]);
function glassboxCli(args: WordInfo[], acc: Acc): void {
  const sub = (operands(args)[0]?.value ?? "").toLowerCase();
  const mutating = GLASSBOX_MUTATING.has(sub) || (sub === "doctor" && hasFlag(args, "--fix"));
  if (mutating || args.some((a) => a.value === null)) acc.protect("CP-SELF-003", "changes Glassbox protection settings");
}

function projectTool(rest: WordInfo[], c: Ctx2, unwrapDepth: number): void {
  const h = rest[0];
  if (!h || h.value === null) { c.acc.unanalyzable("package runner with a non-literal package"); return; }
  const n = (() => { const v = h.value as string; const slash = v.lastIndexOf("/"); const at = v.indexOf("@", slash + 1); return (at >= 0 ? v.slice(0, at) : v).split("/").pop() ?? ""; })();
  // A package runner launching the Glassbox CLI (npx glassbox allow …, pnpm dlx @glassbox-ai/…).
  if ((h.value as string).toLowerCase().includes("glassbox")) { glassboxCli(rest.slice(1), c.acc); return; }
  // A package runner starting an agent CLI (npx @openai/codex --yolo, npx @anthropic-ai/claude-code …).
  const agentBin = agentPackageBin(h.value as string) ?? (agentCliFor(h.value as string) ? (h.value as string) : undefined);
  if (agentBin === "claude" || (h.value as string).toLowerCase() === "claude") return claudeCommand(rest.slice(1), c);
  const agentCli = agentBin !== undefined ? agentCliFor(agentBin) : undefined;
  if (agentCli) { agentCliCommand(agentCli, rest.slice(1).map((a) => a.value), envOf(c.cmd), c.acc); return; }
  if (PROJECT.has(n) || READ.has(n)) { c.acc.tag("write-reversible", "exec.project-code"); return; }
  if (unwrapDepth < 4 && (n === "rimraf" || n === "del-cli")) { c.acc.tag("high-risk", "fs.delete"); return; }
  c.acc.tag("write-reversible", "exec.project-code");
}

function writeOps(targets: WordInfo[], c: Ctx2, tag: "fs.write" | "fs.move"): void {
  const { acc, pctx } = c;
  acc.tag("write-reversible", tag);
  for (const t of targets) {
    const np = npOf(t, pctx);
    if (np === null) { acc.unanalyzable("writes to a path that isn't known statically"); continue; }
    writeTarget(np, acc, pctx, t.glob);
  }
}

function remove(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc, pctx } = c;
  acc.tag("high-risk", "fs.delete");
  const recursive = lower === "rm" && hasFlag(args, "-r", "-R", "--recursive");
  const noPreserve = args.some((a) => a.value === "--no-preserve-root");
  if (noPreserve) destroy(acc, "deletes the filesystem root");
  const targets = operands(args, new Set(["-n", "--iterations", "-s", "--size"]));
  const home = normalizePath("~", pctx).path;
  for (const t of targets) {
    const np = npOf(t, pctx);
    if (np === null) { acc.unanalyzable("deletes a path that isn't known statically"); continue; }
    writeTarget(np, acc, pctx, t.glob);
    const raw = t.pathValue ?? "";
    const p = np.path;
    const rootLevel = p !== null && /^(\/[^/]*|[a-z]:\/[^/]*)$/i.test(p);
    const isHome = p !== null && home !== null && (p === home || p === home + "/*");
    const star = raw === "*" || raw === "/*" || raw === "~/*" || raw === "$HOME/*" || raw === "." || raw === "./" || raw === ".." || raw === "./*";
    if ((recursive || raw.endsWith("*")) && (rootLevel || isHome || star || p === "/")) destroy(acc, "deletes a whole filesystem, home directory or project");
    else if (recursive && isGitDir(p)) destroy(acc, "deletes a repository's .git directory, its whole history");
    else if (recursive && homeTopLevel(p, pctx)) destroy(acc, "deletes a whole folder in the home directory");
    if (lower === "shred" && p !== null && !scratch(p, c.st.pctx.cwd)) destroy(acc, "shreds files outside the project, which can't be recovered");
    if (p !== null && isLogOrHistory(p)) acc.find("CP-ACTION-030", `${lower} on a log or shell history file`);
  }
}

/** scheme://…, file:… or scp-style user@host:path. String code, not a regex (ReDoS test). */
function isRepoUrl(d: string): boolean {
  const l = d.toLowerCase();
  if (l.startsWith("file:")) return true;
  const s = l.indexOf("://");
  if (s > 0 && /^[a-z][a-z0-9+.-]*$/.test(l.slice(0, s))) return true;
  const at = l.indexOf("@");
  const colon = l.indexOf(":");
  return at > 0 && colon > at + 1 && !l.slice(0, at).includes("/");
}

/** The .git directory of a repository, or everything in it. */
function isGitDir(p: string | null): boolean {
  if (p === null) return false;
  const lp = trimEndChars(p, "/");
  return lp === ".git" || lp.endsWith("/.git") || lp.endsWith("/.git/*");
}

/** Inside the session's project directory (not wherever a `cd` went) or a temp directory. */
function scratch(p: string, cwd: string | null): boolean {
  const lp = p.toLowerCase();
  if (lp.startsWith("/tmp/") || lp.startsWith("/var/tmp/") || lp.startsWith("/private/tmp/")) return true;
  if (cwd === null) return false;
  const lc = trimEndChars(cwd.toLowerCase(), "/");
  return lp.startsWith(lc + "/");
}

/** System logs and shell history files: clearing them hides what happened (warn, CP-ACTION-030). */
function isLogOrHistory(p: string): boolean {
  const lp = p.toLowerCase();
  const base = lp.slice(lp.lastIndexOf("/") + 1);
  return lp.startsWith("/var/log/") || base.endsWith("_history") || base === ".history" || base === "wtmp" || base === "btmp" || base === "lastlog";
}

const FIND_NARROWING = new Set(["-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-newer", "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-size", "-user", "-group", "-perm", "-empty", "-links", "-inum", "-samefile", "-lname", "-ilname", "-maxdepth"]);

function find(args: WordInfo[], c: Ctx2, unwrapDepth: number): void {
  const { acc, pctx } = c;
  if (args.some((a) => a.value === "-delete")) acc.tag("high-risk", "fs.delete");
  // Red team (Step 5): `find . -delete` or `find ~ -exec rm -rf {} +` with nothing narrowing
  // the match deletes everything under the root, like `rm -rf .`.
  const deletes = args.some((a) => a.value === "-delete") || args.some((a, k) => (a.value === "-exec" || a.value === "-execdir") && ["rm", "unlink", "shred"].includes(args[k + 1]?.value ?? ""));
  if (deletes && !args.some((a) => FIND_NARROWING.has(a.value ?? ""))) {
    const roots = [];
    for (const a of args) { if ((a.value ?? "-").startsWith("-") || a.value === "(" || a.value === "!") break; roots.push(a); }
    if (roots.length === 0) roots.push({ word: { parts: [], raw: ".", brace: false }, value: ".", pathValue: ".", suffix: ".", dynamic: false, glob: false, substs: [] } as WordInfo);
    const home = normalizePath("~", pctx).path;
    const cwd = pctx.cwd !== null ? normalizePath(pctx.cwd, pctx).path : null;
    for (const r of roots) {
      const np = npOf(r, pctx);
      const p = np?.path ?? null;
      if (r.pathValue === null || p === null || p === "/" || p === home || p === cwd || /^(\/[^/]*|[a-z]:\/[^/]*)$/i.test(p) || (cwd !== null && cwd.startsWith(p + "/"))) {
        destroy(acc, "deletes everything under a project, home or root directory");
        break;
      }
    }
  }
  for (let i = 0; i < args.length; i++) {
    const v = args[i]?.value;
    if (v === "-exec" || v === "-execdir" || v === "-ok" || v === "-okdir") {
      const inner: WordInfo[] = [];
      let j = i + 1;
      while (j < args.length && args[j]?.value !== ";" && args[j]?.value !== "+") { inner.push(args[j] as WordInfo); j++; }
      const h = inner[0];
      if (!h || h.value === null) { acc.unanalyzable("find -exec with a non-literal command"); continue; }
      if (unwrapDepth >= 4) { acc.unanalyzable("too many nested wrappers"); continue; }
      classify(h.value, inner.slice(1).filter((w) => w.value !== "{}"), c.cmd, c.st, acc, c.pctx, c.cwd, c.envPrefix, c.functions, unwrapDepth + 1);
      i = j;
    }
    if (v === "-fprint" || v === "-fprintf" || v === "-fls") acc.tag("write-reversible", "fs.write");
  }
  // find loops forever on `while j < … && args[j] !== ";"` only if inner never ends; bounded by args length.
}

/** systemd-run timers, at, schtasks, sc, launchctl and systemctl enable. True when handled. */
function scheduledJobCommand(lower: string, args: WordInfo[], c: Ctx2): boolean {
  const { acc, pctx } = c;
  const vals = args.map((a) => a.value ?? "");
  const lv = vals.map((v) => v.toLowerCase());
  const abs = (f: string) => normalizePath(f, pctx).path ?? f;
  if (lower === "systemd-run") {
    const sched: string[] = [];
    const withValue = new Set(["--unit", "-u", "--property", "-p", "--description", "--slice", "--setenv", "-E", "--uid", "--gid", "--working-directory", "-M", "--machine", "--nice", "--timer-property"]);
    let i = 0;
    for (; i < vals.length; i++) {
      const v = vals[i] as string;
      if (v.startsWith("--on-")) { const eq = v.indexOf("="); if (eq > 0) sched.push(v); else { sched.push(`${v} ${vals[i + 1] ?? ""}`.trim()); i++; } continue; }
      if (withValue.has(v)) { i++; continue; }
      if (v.startsWith("-")) continue;
      break;
    }
    if (sched.length === 0) return false; // a transient unit that runs now, not later
    acc.scheduleJob({ kind: "systemd", verb: "creates", path: null, schedule: sched.join(", "), files: commandFiles(vals.slice(i).join(" ")).map(abs) });
    return true;
  }
  if (lower === "at" || lower === "batch") {
    if (vals.length === 0 && lower === "at") return false;
    if (vals.every((v) => v === "-l" || v === "-V")) return true; // listing
    if (vals.includes("-r") || vals.includes("-d")) { acc.scheduleJob({ kind: "at", verb: "removes", path: null, schedule: `job ${vals.filter((v) => !v.startsWith("-")).join(" ")}`, files: [] }); return true; }
    const fIdx = vals.indexOf("-f");
    const file = fIdx >= 0 ? vals[fIdx + 1] : undefined;
    const spec = vals.filter((v, k) => !v.startsWith("-") && !(fIdx >= 0 && k === fIdx + 1)).join(" ");
    acc.scheduleJob({ kind: "at", verb: "creates", path: null, schedule: lower === "batch" ? "when the system load allows" : spec || null, files: file ? [abs(file)] : [] });
    return true;
  }
  if (lower === "schtasks" || lower === "schtasks.exe") {
    const op = lv.find((v) => ["/create", "-create", "/delete", "-delete", "/change", "-change", "/run", "-run"].includes(v));
    if (op === undefined) return true; // /query and the rest: listing
    if (op.endsWith("delete")) { acc.scheduleJob({ kind: "task-scheduler", verb: "removes", path: null, schedule: `task ${vals[lv.indexOf("/tn") + 1] ?? ""}`.trim(), files: [] }); return true; }
    if (op.endsWith("run")) { acc.tag("high-risk", "exec.unknown"); acc.reason("runs a scheduled task now"); return true; }
    const j = schtasksJob(lv.map((v, k) => (v.startsWith("/") || v.startsWith("-") ? "/" + v.slice(1) : vals[k] as string)));
    acc.scheduleJob({ kind: "task-scheduler", verb: op.endsWith("create") ? "creates" : "changes", path: null, schedule: j.schedule, files: j.files });
    return true;
  }
  if (lower === "sc" || lower === "sc.exe") {
    const sub = lv[0] ?? "";
    if (!["create", "config", "delete"].includes(sub)) return false;
    const after = (key: string) => { const k = lv.findIndex((v) => v === key || v.startsWith(key)); if (k < 0) return null; const v = vals[k] as string; return v.length > key.length ? v.slice(key.length) : vals[k + 1] ?? null; };
    const bin = after("binpath=");
    const start = after("start=");
    acc.scheduleJob({ kind: "service", verb: sub === "delete" ? "removes" : sub === "create" ? "creates" : "changes", path: null, schedule: start ? `start=${start}` : sub === "delete" ? `service ${vals[1] ?? ""}` : "as a Windows service", files: bin ? commandFiles(bin) : [] });
    return true;
  }
  if (lower === "launchctl") {
    const sub = lv[0] ?? "";
    const plist = operands(args).slice(1).map((o) => o.pathValue).filter((p): p is string => p !== null).pop();
    if (["load", "bootstrap", "enable", "submit"].includes(sub)) {
      acc.scheduleJob({ kind: "launchd", verb: "creates", path: plist ? abs(plist) : null, schedule: "as the plist says (loaded now)", files: plist ? [abs(plist)] : [] });
      return true;
    }
    if (["unload", "bootout", "remove", "disable"].includes(sub)) { acc.scheduleJob({ kind: "launchd", verb: "removes", path: plist ? abs(plist) : null, schedule: null, files: [] }); return true; }
    return false;
  }
  if (lower === "systemctl") {
    const sub = lv.find((v) => !v.startsWith("-")) ?? "";
    const units = vals.filter((v) => !v.startsWith("-") && v.toLowerCase() !== sub);
    if (sub === "enable" || ((sub === "start" || sub === "restart") && units.some((u) => u.endsWith(".timer")))) {
      acc.scheduleJob({ kind: "systemd", verb: "creates", path: null, schedule: sub === "enable" ? `enabled at boot or login: ${units.join(", ")}` : `timer ${units.join(", ")}`, files: [] });
      return true;
    }
    return false;
  }
  return false;
}

/** Is `p` inside `dir` (the session's project directory)? */
function insideDir(p: string, dir: string | null, pctx: PathCtx): boolean {
  if (dir === null) return false;
  const fold = (s: string) => (pctx.caseInsensitive ? s.toLowerCase() : s);
  const root = fold(trimEndChars(dir, "/"));
  const lp = fold(p);
  return lp === root || lp.startsWith(root + "/");
}

/** Why a chmod mode is risky (world-writable, setuid/setgid), or null. Unknown modes are risky. */
function chmodRisk(mode: string): string | null {
  if (/^[0-7]{3,4}$/.test(mode)) {
    const d = mode.padStart(4, "0");
    if ((Number(d[0]) & 6) !== 0) return "sets the setuid or setgid bit";
    if ((Number(d[3]) & 2) !== 0) return "makes a file writable by everyone";
    return null;
  }
  // Symbolic: comma-separated clauses like u+x, go-w, a=rwx.
  for (const clause of mode.split(",")) {
    const m = /^([ugoa]*)([-+=])([rwxXst]*)$/.exec(clause);
    if (!m) return "uses a permission mode Glassbox can't read";
    const who = m[1] ?? "", op = m[2] ?? "", perms = m[3] ?? "";
    if (op === "-") continue;
    if (perms.includes("s")) return "sets the setuid or setgid bit";
    if (perms.includes("w") && (who.includes("o") || who.includes("a"))) return "makes a file writable by everyone";
  }
  return null;
}

function perm(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc, pctx } = c;
  const targets = operands(args);
  if (lower === "chmod") {
    const ops = operands(args);
    const mode = ops[0]?.value ?? "";
    const files = ops.slice(1);
    // Rev 8 (Q2): chmod asks only when recursive, outside the project, world-writable or
    // setuid/setgid. Anything else is an ordinary, reversible change.
    const recursive = hasFlag(args, "-R", "--recursive") || args.some((a) => /^-[a-zA-Z]*R/.test(a.value ?? ""));
    let outside = false;
    for (const f of files) {
      const np = npOf(f, pctx);
      if (np === null) { acc.unanalyzable("changes permissions on a path that isn't known statically"); continue; }
      writeTarget(np, acc, pctx);
      if (np.path === null || !insideDir(np.path, c.st.pctx.cwd, pctx)) outside = true;
    }
    const risky = chmodRisk(mode);
    if (!recursive && !outside && risky === null) { acc.tag("write-reversible", "fs.write"); return; }
    acc.tag("high-risk", "perm.change");
    acc.reason(risky ?? (recursive ? "changes permissions recursively" : "changes permissions outside the project"));
    return;
  }
  for (const t of targets) {
    const np = npOf(t, pctx);
    if (np) writeTarget(np, acc, pctx);
  }
  acc.tag("high-risk", "perm.change");
  acc.reason("changes ownership, permissions or accounts");
}

function rsync(args: WordInfo[], c: Ctx2): void {
  const ops = operands(args, new Set(["-e", "--rsh", "--exclude", "--include", "--filter", "-f"]));
  const remotes = ops.filter((o) => remoteOperand(o.value));
  const loop = remotes.length > 0 && allLoopback(remotes.map((o) => o.value));
  if (remotes.length > 0 && !loop) { c.acc.tag("high-risk", "net.egress"); c.acc.network = true; }
  // Local sources sent to a remote destination are uploads.
  const last = ops[ops.length - 1];
  if (last && remoteOperand(last.value)) for (const o of ops.slice(0, -1)) if (!remoteOperand(o.value)) uploadFile(o, c, loop);
  if (args.some((a) => a.value === "--delete" || (a.value ?? "").startsWith("--delete"))) c.acc.tag("high-risk", "fs.delete");
  const dest = ops[ops.length - 1];
  if (dest) writeOps([dest], c, "fs.write");
}

/** Is this remote operand (scp/rsync) on another host? host:path, user@host:path, rsync://. */
function remoteOperand(v: string | null): boolean {
  if (v === null) return true;
  if (v.startsWith("rsync://")) return true;
  const colon = v.indexOf(":");
  const slash = v.indexOf("/");
  return colon > 0 && (slash < 0 || colon < slash) && !/^[A-Za-z]:$/.test(v.slice(0, 2));
}

function uploadFile(file: WordInfo | string, c: Ctx2, loop: boolean): void {
  if (loop) return;
  const np = typeof file === "string" ? normalizePath(file, c.pctx) : npOf(file, c.pctx);
  const label = typeof file === "string" ? file : (file.pathValue ?? file.suffix ?? "?");
  const raw = typeof file === "string" ? file : file.pathValue;
  recordUpload(c.acc, classifyUpload(np, c.pctx, c.st.pctx.cwd, raw), label.slice(0, 80));
}

function network(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc, pctx } = c;
  // Every destination on this machine (curl http://localhost:3000, scp x localhost:) isn't egress.
  let dests: (string | null)[] = [];
  if (lower === "curl" || lower === "wget" || lower === "http" || lower === "https") {
    dests = args.filter((a) => a.value === null || (a.value.includes("://") && !a.value.startsWith("-"))).map((a) => a.value);
    const bare = operands(args, new Set(["-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--json", "-T", "--upload-file", "-F", "--form", "-o", "--output", "-O", "-H", "--header", "-u", "--user", "-X", "--request", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "-x", "--proxy", "--post-file", "--body-file", "--post-data", "--header"]));
    for (const o of bare) if (o.value !== null && !o.value.includes("://") && /^(localhost|127\.|\[::1\])/i.test(o.value)) dests.push(o.value);
  } else if (lower === "scp" || lower === "sftp") {
    dests = operands(args, new Set(["-P", "-i", "-o", "-F", "-c", "-l", "-S", "-J"])).filter((o) => remoteOperand(o.value)).map((o) => o.value);
  }
  const loop = allLoopback(dests);
  if (loop) { acc.reason("talks only to this machine (loopback)"); }
  else { acc.tag("high-risk", "net.egress"); acc.network = true; }
  if (lower === "curl" || lower === "wget" || lower === "http" || lower === "https") {
    for (let i = 0; i < args.length; i++) {
      const v0 = args[i]?.value ?? "";
      // wget accepts --opt=value; curl takes the value as the next word.
      const eq = v0.startsWith("--") ? v0.indexOf("=") : -1;
      const v = eq > 0 ? v0.slice(0, eq) : v0;
      const next = eq > 0 ? ({ ...(args[i] as WordInfo), value: v0.slice(eq + 1), pathValue: v0.slice(eq + 1) } as WordInfo) : args[i + 1];
      if (!next) continue;
      const nv = next.value;
      let file: string | null | undefined;
      if (v === "-T" || v === "--upload-file" || v === "--post-file" || v === "--body-file") file = next.value === null ? null : next.pathValue ?? "";
      else if (v === "-d" || v === "--data" || v === "--data-binary" || v === "--json") file = nv === null ? undefined : nv.startsWith("@") ? nv.slice(1) : undefined;
      else if (v === "--data-urlencode") { if (nv !== null) { const at = nv.indexOf("@"); const eqi = nv.indexOf("="); if (at >= 0 && (eqi < 0 || at < eqi)) file = nv.slice(at + 1); } }
      else if (v === "-F" || v === "--form") {
        if (nv === null) file = null;
        else { const e = nv.indexOf("="); const rest = e >= 0 ? nv.slice(e + 1) : ""; if (rest.startsWith("@") || rest.startsWith("<")) file = (rest.slice(1).split(";")[0] ?? ""); }
      }
      if (file === null) { if (!loop) recordUpload(acc, "outside", "a file named at run time"); }
      else if (file !== undefined && file !== "" && file !== "-") {
        readTarget(normalizePath(file, pctx), acc, pctx, false);
        uploadFile(file, c, loop);
      }
      if ((v === "-o" || v === "--output" || (v === "-O" && lower === "wget")) && args[i + 1]) {
        const np = npOf(args[i + 1] as WordInfo, pctx);
        if (np) writeTarget(np, acc, pctx);
      }
    }
  }
  if (lower === "scp" || lower === "sftp") {
    const ops = operands(args, new Set(["-P", "-i", "-o", "-F", "-c", "-l", "-S", "-J"]));
    const last = ops[ops.length - 1];
    const toRemote = last !== undefined && remoteOperand(last.value);
    for (const o of ops.slice(0, -1)) {
      if (o.value !== null && remoteOperand(o.value)) continue; // a remote source: a download
      if (o.value !== null) readTarget(normalizePath(o.value, pctx), acc, pctx, true);
      if (toRemote) uploadFile(o, c, loop);
    }
  }
  if (lower === "ssh") {
    const ops = operands(args, new Set(["-p", "-i", "-o", "-F", "-l", "-L", "-R", "-D", "-J", "-b", "-c", "-e", "-m", "-O", "-Q", "-S", "-W", "-w", "-E", "-B", "-I"]));
    if (ops.length > 1) acc.reason("runs a command on a remote host");
  }
}

function docker(args: WordInfo[], c: Ctx2): void {
  const { acc } = c;
  const sub = operands(args, new Set(["-H", "--host", "--context", "-c", "--config", "-l", "--log-level"]))[0]?.value ?? "";
  if (["pull", "login", "search"].includes(sub)) { acc.tag("high-risk", "net.egress"); acc.network = true; return; }
  if (sub === "push") { acc.tag("high-risk", "publish.public", "net.egress"); acc.network = true; return; }
  const vals = args.map((a) => a.value ?? "");
  if ((sub === "system" && vals.includes("prune")) || (sub === "volume" && (vals.includes("prune") || vals.includes("rm")))) {
    acc.tag("high-risk", "fs.destroy", "fs.delete");
    acc.reason("deletes Docker volumes or all unused data, which can't be recovered");
    return;
  }
  if (["rm", "rmi", "prune", "kill"].includes(sub) || args.some((a) => a.value === "prune")) { acc.tag("high-risk", "fs.delete"); return; }
  if (["ps", "images", "inspect", "logs", "version", "info", "stats", "top", "history", "port", "diff"].includes(sub)) return;
  if (sub === "run" && args.some((a) => a.value === "--privileged" || (a.value ?? "").startsWith("-v=/:") || a.value === "-v" )) acc.reason("runs a container with host access");
  acc.tag("write-reversible", "exec.unknown");
}

/** aws s3 rm --recursive, aws s3 rb --force, gcloud storage rm -r, gsutil rm -r. */
function cloudBulkDelete(lower: string, vals: string[]): boolean {
  const recursive = vals.includes("--recursive") || vals.includes("-r") || vals.includes("-R");
  if (lower === "aws") return vals.includes("s3") && ((vals.includes("rm") && recursive) || (vals.includes("rb") && vals.includes("--force")));
  if (lower === "gcloud") return vals.includes("storage") && vals.includes("rm") && recursive;
  if (lower === "gsutil") return vals.includes("rm") && recursive;
  return false;
}

/** --context naming a local cluster (kind, minikube, Docker Desktop…) or --server on loopback. */
function localKubeContext(args: WordInfo[]): boolean {
  const vals = args.map((a) => a.value ?? "");
  const valueOf = (flag: string) => {
    for (let i = 0; i < vals.length; i++) {
      if (vals[i] === flag) return vals[i + 1] ?? "";
      if ((vals[i] ?? "").startsWith(flag + "=")) return (vals[i] ?? "").slice(flag.length + 1);
    }
    return null;
  };
  const ctxName = (valueOf("--context") ?? "").toLowerCase();
  if (/^(kind|minikube|docker-desktop|docker-for-desktop|rancher-desktop|orbstack|colima|microk8s|k3d-.+|kind-.+)$/.test(ctxName)) return true;
  const server = valueOf("--server") ?? valueOf("-s");
  return server !== null && allLoopback([server]);
}

function deploy(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc } = c;
  acc.network = true;
  const vals = args.map((a) => a.value ?? "");
  const sub = operands(args, new Set(["-n", "--namespace", "--context", "--kubeconfig", "--project", "--region", "--profile", "-c", "-f", "--chdir", "-o", "--output"]))[0]?.value ?? "";
  const readSubs = new Set(["get", "describe", "logs", "list", "ls", "show", "status", "plan", "validate", "fmt", "version", "init", "whoami", "config", "top", "explain", "diff", "history", "output", "preview", "info", "inspect", "help", "--version", "-v", "dev", "login"]);
  if (cloudBulkDelete(lower, vals)) {
    acc.tag("high-risk", "fs.destroy", "net.egress");
    acc.reason("deletes cloud storage objects in bulk, which can't be recovered");
    return;
  }
  if (lower === "kubectl") {
    // Rev 8 (Q2): label/annotate warn; delete/apply/scale ask unless the context is local.
    if (sub === "label" || sub === "annotate") { acc.tag("high-risk", "net.egress"); acc.reason(`kubectl ${sub} changes object metadata`); return; }
    if (sub === "delete" || sub === "apply" || sub === "scale") {
      if (localKubeContext(args)) { acc.tag("high-risk", "net.egress"); acc.reason(`kubectl ${sub} on a local cluster`); return; }
      acc.tag("high-risk", "infra.change", "net.egress");
      acc.reason(`kubectl ${sub} on a cluster that isn't known to be local`);
      return;
    }
  }
  if (lower === "vercel") {
    if (vals.includes("--prod") || vals.includes("--production") || sub === "promote") { acc.tag("high-risk", "deploy.prod", "net.egress"); return; }
    if (["ls", "list", "inspect", "logs", "whoami", "env", "pull", "dev", "build", "link"].includes(sub)) { acc.tag("high-risk", "net.egress"); return; }
    acc.tag("high-risk", "deploy.other", "net.egress");
    return;
  }
  if (lower === "netlify") {
    if (sub === "deploy" && (vals.includes("--prod") || vals.includes("--production"))) { acc.tag("high-risk", "deploy.prod", "net.egress"); return; }
    acc.tag("high-risk", sub === "deploy" ? "deploy.other" : "net.egress", "net.egress");
    return;
  }
  if (["fly", "flyctl", "wrangler", "firebase", "heroku", "railway", "render", "eb", "serverless", "sls"].includes(lower)) {
    if (["deploy", "publish", "release", "promote"].includes(sub) || vals.includes("deploy")) { acc.tag("high-risk", "deploy.prod", "net.egress"); return; }
    acc.tag("high-risk", "net.egress");
    return;
  }
  if (readSubs.has(sub)) { acc.tag("high-risk", "net.egress"); return; }
  const mutating = ["apply", "delete", "destroy", "rollout", "scale", "patch", "edit", "replace", "create", "drain", "cordon", "taint", "install", "upgrade", "uninstall", "rollback", "up", "import", "state", "set", "run", "exec", "cp", "label", "annotate", "expose", "autoscale", "deploy", "remove", "update", "put", "terminate", "start", "stop"];
  if (mutating.includes(sub) || vals.some((v) => ["delete", "create", "update", "put", "terminate", "remove", "deploy", "apply", "destroy"].some((m) => v === m || v.startsWith(m + "-")))) {
    acc.tag("high-risk", "infra.change", "net.egress");
    return;
  }
  acc.tag("high-risk", "net.egress");
}

function git(args: WordInfo[], c: Ctx2): void {
  const { acc, pctx } = c;
  // Global options before the subcommand.
  let i = 0;
  while (i < args.length) {
    const v = args[i]?.value ?? null;
    if (v === null) { acc.unanalyzable("git option isn't literal"); return; }
    if (v === "-C") { const p = args[i + 1]; if (!p || p.pathValue === null) { c.cwd.cwd = null; } i += 2; continue; }
    if (v === "-c") {
      const kv = args[i + 1]?.value ?? null;
      if (kv === null) { acc.unanalyzable("git -c value isn't literal"); return; }
      if (DANGEROUS_GIT_CONFIG.test(kv.split("=")[0] ?? "")) { acc.tag("high-risk", "config.agent"); acc.reason("git -c sets a value git runs as a command"); }
      i += 2;
      continue;
    }
    if (v.startsWith("--git-dir") || v.startsWith("--work-tree") || v.startsWith("--namespace") || v === "--no-pager" || v === "-P" || v === "--bare" || v === "-p" || v === "--paginate" || v === "--no-replace-objects" || v === "--literal-pathspecs" || v.startsWith("--exec-path") || v === "--no-optional-locks") {
      if ((v === "--git-dir" || v === "--work-tree" || v === "--namespace") && args[i + 1]) i++;
      i++;
      continue;
    }
    break;
  }
  const sub = args[i]?.value ?? "";
  const rest = args.slice(i + 1);
  const rv = rest.map((a) => a.value);
  const ops = operands(rest, new Set(["-m", "-F", "--file", "-C", "-c", "--author", "--date", "-b", "-B", "--format", "--pretty", "-n", "--depth", "-o", "--origin", "-u", "-x", "--exclude", "-e"]));
  const commit = () => acc.tag("write-reversible", "vcs.commit");
  const discard = (why: string) => { acc.tag("high-risk", "vcs.discard-changes"); acc.reason(why); };
  const net = (...extra: ("vcs.push" | "net.fetch.vcs" | "vcs.force-push")[]) => { acc.tag("high-risk", "net.egress", ...extra); acc.network = true; };
  switch (sub) {
    case "status": case "log": case "diff": case "show": case "rev-parse": case "describe": case "blame": case "ls-files": case "ls-tree": case "cat-file":
    case "shortlog": case "reflog": case "grep": case "merge-base": case "rev-list": case "name-rev": case "for-each-ref": case "version": case "help":
    case "count-objects": case "whatchanged": case "show-ref": case "check-ignore": case "var": case "show-branch": case "range-diff": case "cherry": case "verify-commit": case "verify-tag": case "fsck":
      if (sub === "reflog" && ["expire", "delete"].includes(rv[0] ?? "")) discard("deletes reflog entries");
      return;
    case "branch": {
      if (rv.some((v) => v === "-D" || v === "--delete" && rv.includes("--force") || v === "-df" || v === "-fd")) { discard("force-deletes a branch"); return; }
      if (rv.some((v) => v === "-d" || v === "--delete" || v === "-m" || v === "-M" || v === "-c" || v === "-C" || v === "-u" || v === "--set-upstream-to" || v === "-f" || v === "--force")) { commit(); return; }
      if (ops.length > 0 && !rv.some((v) => v === "--list" || v === "-l" || v === "--contains" || v === "--merged" || v === "--no-merged" || v === "--points-at")) { commit(); return; }
      return;
    }
    case "tag": {
      if (rv.some((v) => v === "-d" || v === "--delete")) { commit(); return; }
      if (ops.length > 0 && !rv.some((v) => v === "-l" || v === "--list")) commit();
      return;
    }
    case "remote": {
      if ((rv[0] === "add" || rv[0] === "set-url") && rv.length >= 3) {
        const name = operands(rest.slice(1), new Set(["-t", "-m", "--track", "--master"]))[0]?.value ?? null;
        acc.newRemotes.push(name ?? "\u0000dynamic");
      }
      if (["add", "remove", "rm", "rename", "set-url", "set-head", "prune"].includes(rv[0] ?? "")) { commit(); return; }
      if (rv[0] === "update") net("net.fetch.vcs");
      return;
    }
    case "stash": {
      const s = rv[0] ?? "";
      if (s === "list" || s === "show") return;
      if (s === "drop" || s === "clear") { discard("deletes stashed changes"); return; }
      commit();
      return;
    }
    case "config": {
      const getOnly = rv.some((v) => v === "--get" || v === "--get-all" || v === "--list" || v === "-l" || v === "--get-regexp" || v === "--show-origin" || v === "get" || v === "list");
      if (getOnly) return;
      const key = ops[0]?.value ?? null;
      if (key === null) { acc.unanalyzable("git config key isn't literal"); return; }
      if (ops.length >= 2 || rv.some((v) => v === "--add" || v === "--unset" || v === "--replace-all")) {
        if (DANGEROUS_GIT_CONFIG.test(key)) { acc.tag("high-risk", "config.agent"); acc.reason("sets a git value that git later runs as a command"); return; }
        commit();
      }
      return;
    }
    case "add": case "commit": case "switch": case "merge": case "cherry-pick": case "revert": case "mv": case "apply": case "am": case "notes": case "init":
    case "bisect": case "sparse-checkout": case "update-index": case "worktree": case "gc": case "maintenance": case "pull_local": case "format-patch": case "bundle": case "archive":
      if (sub === "worktree" && (rv[0] === "remove" || rv[0] === "prune") && rv.includes("--force")) { discard("removes a worktree with uncommitted changes"); return; }
      if (sub === "merge" && rv.includes("--abort")) { discard("aborts a merge, discarding its changes"); return; }
      commit();
      return;
    case "checkout": {
      const dd = rv.indexOf("--");
      if (dd >= 0) { discard("discards uncommitted changes to files"); return; }
      if (rv.some((v) => v === "-f" || v === "--force")) { discard("discards uncommitted changes"); return; }
      if (rv.some((v) => v === "-b" || v === "-B" || v === "--orphan" || v === "-t" || v === "--track")) { commit(); return; }
      if (ops.length === 1 && (ops[0]?.value === "." || ops[0]?.value === "./" || ops[0]?.value === "*")) { discard("discards uncommitted changes to files"); return; }
      if (ops.length >= 2) { discard("discards uncommitted changes to files"); return; }
      commit();
      return;
    }
    case "restore": {
      if (rv.includes("--staged") && !rv.includes("--worktree") && !rv.includes("-W")) { commit(); return; }
      discard("discards uncommitted changes to files");
      return;
    }
    case "reset": {
      if (rv.includes("--hard") || rv.includes("--merge")) { discard("discards uncommitted changes"); return; }
      commit();
      return;
    }
    case "clean": {
      if (rv.some((v) => v === "-n" || v === "--dry-run")) return;
      acc.tag("high-risk", "fs.delete", "vcs.discard-changes");
      acc.reason("deletes untracked files, which git can't restore");
      return;
    }
    case "rm": {
      if (rv.includes("--cached")) { commit(); return; }
      acc.tag("high-risk", "fs.delete");
      for (const o of ops) { const np = npOf(o, pctx); if (np) writeTarget(np, acc, pctx); }
      return;
    }
    case "rebase": {
      if (rv.some((v) => v === "--abort" || v === "--quit" || v === "--skip")) { acc.tag("high-risk", "vcs.discard-changes"); return; }
      acc.tag("high-risk", "vcs.commit");
      acc.reason("rebases, which rewrites local commits");
      return;
    }
    case "filter-branch": case "filter-repo": case "replace":
      acc.tag("high-risk", "vcs.history-rewrite");
      acc.reason("rewrites repository history");
      return;
    case "push": {
      net("vcs.push");
      const force = rv.some((v) => v !== null && (v === "-f" || v === "--force" || v.startsWith("--force-with-lease") || v === "--force-if-includes" || v === "--mirror" || v === "--delete" || v === "-d" || v === "--prune" || (/^-[a-zA-Z]+$/.test(v) && v.includes("f"))));
      const refspecs = operands(rest, new Set(["--repo", "-o", "--push-option", "--receive-pack", "--exec"])).slice(1);
      const plusOrColon = refspecs.some((r) => r.value === null || r.value.startsWith("+") || r.value.startsWith(":"));
      if (force || plusOrColon) { acc.tags.add("vcs.force-push"); acc.reason("force-pushes or deletes remote history"); }
      const target = operands(rest, new Set(["--repo", "-o", "--push-option", "--receive-pack", "--exec"]))[0];
      const repoOpt = rest.find((a) => (a.value ?? "").startsWith("--repo="))?.value?.slice(7);
      const dest = repoOpt ?? (target ? target.value : undefined);
      if (dest === null) acc.pushedTo.push("\u0000dynamic");
      else if (dest !== undefined) {
        if (isRepoUrl(dest)) acc.find("CP-EXFIL-034", "pushes straight to a repository URL instead of a configured remote");
        else acc.pushedTo.push(dest);
      }
      return;
    }
    case "pull": case "fetch": case "clone": case "ls-remote": case "submodule":
      net("net.fetch.vcs");
      if (sub === "pull" && rv.includes("--force")) acc.tags.add("vcs.discard-changes");
      if (sub === "clone") { const dest = ops[1]; if (dest) { const np = npOf(dest, pctx); if (np) writeTarget(np, acc, pctx); } }
      return;
    case "send-email": case "request-pull":
      acc.tag("high-risk", "message.send", "net.egress");
      acc.network = true;
      return;
    case "": return;
    case "lfs":
      if (["push", "pull", "fetch", "clone"].includes(rv[0] ?? "")) { net("net.fetch.vcs"); return; }
      acc.tag("write-reversible", "exec.unknown");
      return;
    case "flow": case "absorb": case "annex": case "branchless": case "machete": case "town": case "extras": case "crypt": case "secret":
      acc.tag("write-reversible", "exec.unknown");
      return;
    default:
      if (args[i]?.value === null) { acc.unanalyzable("git subcommand isn't literal"); return; }
      // Red team (Step 5): `git config alias.p 'push -f'` earlier, then `git p` now.
      // An unknown subcommand may be an alias for anything, including a force-push.
      acc.unanalyzable(`unknown git subcommand '${sub.slice(0, 30)}' (it could be an alias)`);
  }
}

function gh(args: WordInfo[], c: Ctx2): void {
  const { acc } = c;
  acc.tag("high-risk", "net.egress");
  acc.network = true;
  const vals = args.map((a) => a.value ?? "");
  const [a, b] = operands(args, new Set(["-R", "--repo", "-t", "--title", "-b", "--body", "-F", "--body-file", "-m", "--milestone", "-l", "--label", "-a", "--assignee", "-B", "--base", "-H", "--head", "-L", "--limit", "-q", "--jq", "--json", "-r", "--reviewer", "-n", "--notes"])).map((x) => x.value ?? "");
  // Pull requests and issues are conversations with the repo's collaborators: message.send
  // (asks by default; can be remembered). Releases, gists, repos, secrets and workflows publish
  // or change what others get: publish.public (hard floor).
  const message = (a === "pr" && ["create", "comment", "merge", "review", "close", "reopen", "edit", "ready"].includes(b ?? "")) ||
    (a === "issue" && ["create", "comment", "close", "reopen", "edit", "delete", "transfer", "lock"].includes(b ?? ""));
  if (message) { acc.tags.add("message.send"); acc.reason("posts or changes a pull request or issue on GitHub"); }
  const publish =
    (a === "release" && ["create", "upload", "edit", "delete"].includes(b ?? "")) ||
    (a === "gist" && ["create", "edit", "delete"].includes(b ?? "")) ||
    (a === "repo" && ["create", "delete", "edit", "rename", "archive", "fork"].includes(b ?? "")) ||
    (a === "secret" && ["set", "delete"].includes(b ?? "")) || (a === "variable" && ["set", "delete"].includes(b ?? "")) ||
    (a === "workflow" && ["run", "enable", "disable"].includes(b ?? "")) || (a === "run" && ["rerun", "cancel", "delete"].includes(b ?? ""));
  if (publish) { acc.tags.add("publish.public"); acc.reason("posts or changes content on GitHub"); }
  if (a === "api" && vals.some((v) => v === "-X" || v === "--method" || v.startsWith("--method=") || v === "-f" || v === "-F" || v === "--field" || v === "--raw-field")) { acc.tags.add("publish.public"); acc.reason("calls the GitHub API with a write method"); }
  if (a === "auth" && ["token", "status"].includes(b ?? "")) acc.reason("reads GitHub credentials");
}

function jsPm(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc } = c;
  const ops = operands(args, new Set(["--filter", "-F", "-C", "--dir", "--prefix", "-w", "--workspace", "--cwd", "--registry", "--tag", "--access", "--otp"]));
  const sub = ops[0]?.value ?? "";
  if (ops[0] && ops[0].value === null) { acc.unanalyzable("package manager subcommand isn't literal"); return; }
  const network = () => { acc.tag("high-risk", "net.egress", "net.fetch.package-manager"); acc.network = true; };
  if (["publish", "unpublish", "deprecate", "dist-tag", "owner", "access"].includes(sub)) { acc.tag("high-risk", "publish.public", "net.egress"); acc.network = true; return; }
  if (["install", "i", "ci", "add", "update", "up", "upgrade", "remove", "rm", "uninstall", "un", "unlink", "link", "dedupe", "import", "fetch", "rebuild", "audit", "outdated", "create", "init_remote", "patch-commit"].includes(sub)) {
    if (sub === "audit" && !args.some((a) => a.value === "fix")) { network(); return; }
    network();
    return;
  }
  if (sub === "" && lower !== "npm") { network(); return; } // bare `pnpm`/`yarn` installs
  if (["ls", "list", "why", "view", "info", "show", "config_get", "root", "bin", "prefix", "help", "-v", "--version", "version_show", "explain", "search", "doctor", "query", "licenses", "store_path"].includes(sub)) return;
  if (sub === "config" && ops[1]?.value === "set") { acc.tag("write-reversible", "fs.write"); return; }
  if (["dlx", "x", "exec", "create"].includes(sub)) {
    acc.tags.add("net.fetch.package-manager");
    // Pass everything after the package, flags included (pnpm dlx @openai/codex --yolo): operands alone drop them.
    const pkg = ops[1];
    const at = pkg === undefined ? -1 : args.indexOf(pkg);
    return projectTool(at >= 0 ? args.slice(at) : ops.slice(1), c, 0);
  }
  acc.tag("write-reversible", "exec.project-code");
}

function otherPm(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc } = c;
  const ops = operands(args, new Set(["-r", "--requirement", "-c", "--constraint", "-t", "--target", "-p", "--package", "--manifest-path", "-C", "--directory"]));
  const sub = ops[0]?.value ?? "";
  const network = () => { acc.tag("high-risk", "net.egress", "net.fetch.package-manager"); acc.network = true; };
  if (["publish", "upload", "push", "release", "yank"].includes(sub) || (lower === "gem" && sub === "push") || (lower === "dotnet" && sub === "nuget" && ops[1]?.value === "push")) { acc.tag("high-risk", "publish.public", "net.egress"); acc.network = true; return; }
  if (lower === "uv" && sub === "pip") return otherPm("pip", ops.slice(1), c);
  if (["install", "add", "get", "update", "upgrade", "sync", "download", "fetch", "lock", "remove", "uninstall", "tap"].includes(sub) || (lower === "go" && sub === "mod" && ["download", "tidy"].includes(ops[1]?.value ?? ""))) {
    if (["apt", "apt-get", "yum", "dnf", "pacman", "apk", "brew", "choco", "winget", "scoop"].includes(lower)) acc.tags.add("perm.change");
    network();
    return;
  }
  if (["list", "show", "freeze", "check", "search", "info", "outdated", "env", "version", "--version", "-V", "help", "tree", "metadata", "doc_open"].includes(sub)) return;
  acc.tag("write-reversible", "exec.project-code");
}

function dbCli(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc } = c;
  acc.tag("high-risk", "net.egress");
  acc.network = true;
  const flag = lower === "psql" ? ["-c", "--command"] : lower === "mysql" || lower === "mariadb" ? ["-e", "--execute"] : lower === "sqlcmd" ? ["-Q", "-q"] : [];
  let sql: string | null | undefined;
  for (let i = 0; i < args.length; i++) if (flag.includes(args[i]?.value ?? "")) sql = args[i + 1]?.value ?? null;
  if (lower === "sqlite3" || lower === "duckdb") { acc.tags.delete("net.egress"); acc.network = false; acc.level = "read"; const ops = operands(args); sql = ops.length >= 2 ? (ops[1]?.value ?? null) : undefined; }
  if (sql === undefined) { acc.tag("high-risk", "db.write"); acc.reason("opens a database session"); return; }
  if (sql === null) { acc.unanalyzable("SQL text isn't literal"); return; }
  acc.merge(analyzeSql(sql, 64 * 1024));
}

/** Classify a native program invocation (used by the PowerShell analyzer). */
export function classifyNative(name: string, args: WordInfo[], cmd: SimpleCommand, st: ShellState, acc: Acc, cwd: { cwd: string | null }): void {
  classify(name, args, cmd, st, acc, { ...st.pctx, cwd: cwd.cwd }, cwd, [], [], 0);
}
