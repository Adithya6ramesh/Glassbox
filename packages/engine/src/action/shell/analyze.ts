// Shell classification (engine-spec §7.3, Q5/Q6 rev 4) over the parsed AST.
import { Acc } from "../acc.js";
import { analyzeInlineCode } from "../inline.js";
import {
  coversProtectedRead, isProtected, isProtectedRead, normalizePath, persistenceLabel, sensitiveLabel, suffixOnly, type NormPath, type PathCtx,
} from "../paths.js";
import { analyzeSql } from "../sql.js";
import { isProtectedWrite } from "../protected-write.js";
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
  const persist = persistenceLabel(np, pctx);
  if (persist) acc.protect("CP-SELF-004", `changes a ${persist}`);
  const p = (np.path ?? np.suffix ?? "").toLowerCase();
  const home = pctx.homeDir.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
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
      if (rest.length === 0) return; // prints the environment
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
  if (lower === "glassbox" || lower === "glassbox.exe") {
    const sub = operands(args)[0]?.value ?? "";
    const mutating = ["mode", "allow", "uninstall", "logout", "login", "install", "pair", "unpair", "config", "set", "disable", "enable", "reset"].includes(sub) || (sub === "doctor" && hasFlag(args, "--fix"));
    if (mutating || args.some((a) => a.value === null)) acc.protect("CP-SELF-003", "changes Glassbox protection settings");
    return;
  }
  if (lower === "claude" || lower === "claude.exe") return claudeCommand(args, c);
  if (lower === "reg" || lower === "reg.exe") {
    const flat = args.map((a) => (a.value ?? a.word.raw)).join(" ").toLowerCase().replace(/[\\/"']/g, "");
    if (flat.includes("policiesclaudecode")) { acc.protect("CP-SELF-003", "changes Claude Code policy in the registry"); return; }
    const sub = (args[0]?.value ?? "").toLowerCase();
    if (["add", "delete", "import", "restore", "load", "copy"].includes(sub)) acc.tag("high-risk", "config.agent");
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
    // Listing is a read; installing, editing or removing a crontab is persistence (CP-SELF-004).
    const flags = args.map((a) => a.value ?? "");
    if (flags.length === 1 && flags[0] === "-l") return;
    acc.protect("CP-SELF-004", "changes scheduled jobs (crontab)");
    return;
  }
  if (lower === "rsync") return rsync(args, c);
  if (NET.has(lower)) return network(lower, args, c);
  if (["docker", "podman"].includes(lower)) return docker(args, c);
  if (["kubectl", "helm", "terraform", "tofu", "pulumi", "vercel", "netlify", "fly", "flyctl", "wrangler", "firebase", "heroku", "aws", "gcloud", "az", "doctl", "serverless", "sls", "cdk", "eb", "railway", "render"].includes(lower)) return deploy(lower, args, c);
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
  if (["kill", "pkill", "killall", "systemctl", "service", "launchctl", "shutdown", "reboot", "halt"].includes(lower)) {
    if (["shutdown", "reboot", "halt"].includes(lower)) acc.tag("high-risk", "infra.change");
    else acc.tag("write-reversible", "exec.unknown");
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
  if (vals.some((v) => v === null)) { acc.tag("high-risk", "exec.nested-agent"); acc.reason("starts a nested agent"); return; }
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
  const hereStr = cmd.redirects.find((r) => r.op === "<<<")?.target;
  const body = cmd.redirects.find((r) => r.heredoc)?.heredoc?.body ?? (hereStr ? wordInfo(hereStr).value ?? "" : "");
  if (body && protectedText(body, pctx)) { acc.protect(body.includes(".key") ? "CP-SELF-002" : "CP-SELF-001", "inline code refers to a protected agent or Glassbox file"); return; }
  const flagsWithCode = new Set(["-c", "-e", "--eval", "-p", "--print", "-E", "-r"]);
  const idx = args.findIndex((a) => a.value !== null && (flagsWithCode.has(a.value) || (lower.startsWith("python") && /^-[A-Za-z]*c$/.test(a.value))));
  if (idx >= 0) {
    const code = args[idx + 1];
    acc.tag("write-reversible", "exec.inline-code");
    if (!code || code.value === null) { acc.unanalyzable("inline code isn't a literal string"); return; }
    // Protected paths inside the code → self-protection (spec §7.6.2).
    if (protectedText(code.value, pctx)) {
      const lowerCode = code.value.toLowerCase();
      acc.protect(lowerCode.includes(".key") || lowerCode.includes("device") ? "CP-SELF-002" : "CP-SELF-001", "inline code refers to a protected agent or Glassbox file");
      return;
    }
    const v = analyzeInlineCode(code.value);
    if (v.unanalyzable) { acc.unanalyzable(v.unanalyzable); return; }
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

function projectTool(rest: WordInfo[], c: Ctx2, unwrapDepth: number): void {
  const h = rest[0];
  if (!h || h.value === null) { c.acc.unanalyzable("package runner with a non-literal package"); return; }
  const n = h.value.replace(/@[^/]*$/, "").split("/").pop() ?? "";
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
  }
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

function perm(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc, pctx } = c;
  const targets = operands(args);
  if (lower === "chmod") {
    const ops = operands(args);
    const mode = ops[0]?.value ?? "";
    const files = ops.slice(1);
    const recursive = hasFlag(args, "-R", "--recursive");
    const benign = /^(\+x|u\+x|a\+x|ug\+x|\+r|u\+rw|u\+r|go-w|o-w|g-w|-x|u\+rwx|755|744|700|644|640|600|0755|0644|0600|0700)$/.test(mode);
    for (const f of files) {
      const np = npOf(f, pctx);
      if (np === null) { acc.unanalyzable("changes permissions on a path that isn't known statically"); continue; }
      writeTarget(np, acc, pctx);
    }
    if (benign && !recursive) { acc.tag("write-reversible", "fs.write"); return; }
    acc.tag("high-risk", "perm.change");
    acc.reason("changes file permissions");
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
  const remote = ops.some((o) => o.value === null || /^[^/]*:/.test(o.value) || (o.value ?? "").startsWith("rsync://"));
  if (remote) { c.acc.tag("high-risk", "net.egress"); c.acc.network = true; }
  if (args.some((a) => a.value === "--delete" || (a.value ?? "").startsWith("--delete"))) c.acc.tag("high-risk", "fs.delete");
  const dest = ops[ops.length - 1];
  if (dest) writeOps([dest], c, "fs.write");
}

function network(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc, pctx } = c;
  acc.tag("high-risk", "net.egress");
  acc.network = true;
  if (lower === "curl" || lower === "wget" || lower === "http" || lower === "https") {
    for (let i = 0; i < args.length; i++) {
      const v = args[i]?.value ?? "";
      const next = args[i + 1];
      const takesFile = ["-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-T", "--upload-file", "-F", "--form", "--post-file", "--body-file"];
      if (takesFile.includes(v) && next) {
        const nv = next.pathValue ?? "";
        const file = v === "-T" || v === "--upload-file" || v === "--post-file" || v === "--body-file" ? nv : nv.includes("@") ? nv.slice(nv.indexOf("@") + 1).split(";")[0] ?? "" : "";
        if (file && file !== "-") readTarget(normalizePath(file, pctx), acc, pctx, false);
        if (next.substs.length > 0) acc.sensitiveArgs ||= false;
      }
      if ((v === "-o" || v === "--output" || v === "-O" && lower === "wget") && next) {
        const np = npOf(next, pctx);
        if (np) writeTarget(np, acc, pctx);
      }
    }
  }
  if (lower === "scp" || lower === "sftp") {
    for (const o of operands(args, new Set(["-P", "-i", "-o", "-F", "-c", "-l", "-S", "-J"]))) {
      if (o.value !== null && !/^[^/]*:/.test(o.value)) readTarget(normalizePath(o.value, pctx), acc, pctx, true);
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
  if (["rm", "rmi", "prune", "kill"].includes(sub) || args.some((a) => a.value === "prune")) { acc.tag("high-risk", "fs.delete"); return; }
  if (["ps", "images", "inspect", "logs", "version", "info", "stats", "top", "history", "port", "diff"].includes(sub)) return;
  if (sub === "run" && args.some((a) => a.value === "--privileged" || (a.value ?? "").startsWith("-v=/:") || a.value === "-v" )) acc.reason("runs a container with host access");
  acc.tag("write-reversible", "exec.unknown");
}

function deploy(lower: string, args: WordInfo[], c: Ctx2): void {
  const { acc } = c;
  acc.network = true;
  const vals = args.map((a) => a.value ?? "");
  const sub = operands(args, new Set(["-n", "--namespace", "--context", "--kubeconfig", "--project", "--region", "--profile", "-c", "-f", "--chdir", "-o", "--output"]))[0]?.value ?? "";
  const readSubs = new Set(["get", "describe", "logs", "list", "ls", "show", "status", "plan", "validate", "fmt", "version", "init", "whoami", "config", "top", "explain", "diff", "history", "output", "preview", "info", "inspect", "help", "--version", "-v", "dev", "login"]);
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
  const publish = (a === "pr" && ["create", "comment", "merge", "review", "close", "reopen", "edit", "ready"].includes(b ?? "")) ||
    (a === "issue" && ["create", "comment", "close", "reopen", "edit", "delete", "transfer", "lock"].includes(b ?? "")) ||
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
  if (["dlx", "x", "exec", "create"].includes(sub)) { acc.tags.add("net.fetch.package-manager"); return projectTool(ops.slice(1), c, 0); }
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
