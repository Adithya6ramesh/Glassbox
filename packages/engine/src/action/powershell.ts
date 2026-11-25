// PowerShell analysis: hand-written tokenizer, alias table,
// cmdlet classes; native programs go through the shell command table.
import { Acc } from "./acc.js";
import { homeTopLevel, isProtected, isProtectedRead, normalizePath, persistenceHit, sensitiveLabel, type NormPath, type PathCtx } from "./paths.js";
import { isProtectedWrite } from "./protected-write.js";
import { classifyNative, type WordInfo } from "./shell/analyze.js";
import { allLoopback, classifyUpload, recordUpload } from "./upload.js";
import { commandFiles } from "./schedule.js";
import { litWord, type SimpleCommand, type Word } from "./shell/parse.js";

class PsUnanalyzable extends Error {
  constructor(readonly reason: string) { super(reason); }
}

type Tok =
  | { k: "word"; v: string; dyn: boolean; pathish: string | null } // bareword (may contain $var text)
  | { k: "str"; v: string; dyn: boolean; subs: string[] }        // string literal; dyn if it expands variables/subexpressions
  | { k: "var"; name: string; tail: string }                     // $name[.prop]
  | { k: "sub"; inner: string; array: boolean }                  // $( … ) / @( … )
  | { k: "paren"; inner: string }                                // ( … )
  | { k: "block"; inner: string }                                // { … }
  | { k: "hash" }                                                // @{ … }
  | { k: "type"; v: string; staticCall: string | null }          // [Type] or [Type]::Member
  | { k: "param"; v: string; value: Tok | null }                 // -Name or -Name:value
  | { k: "op"; v: string }                                       // | ; && || & . newline =
  | { k: "redir"; v: string; target: Tok | null };

const ALIASES = new Map<string, string>([
  ["ls", "get-childitem"], ["dir", "get-childitem"], ["gci", "get-childitem"], ["cat", "get-content"], ["gc", "get-content"], ["type", "get-content"],
  ["sls", "select-string"], ["rm", "remove-item"], ["del", "remove-item"], ["erase", "remove-item"], ["rd", "remove-item"], ["ri", "remove-item"], ["rmdir", "remove-item"],
  ["cp", "copy-item"], ["copy", "copy-item"], ["cpi", "copy-item"], ["mv", "move-item"], ["move", "move-item"], ["mi", "move-item"], ["ren", "rename-item"], ["rni", "rename-item"],
  ["iwr", "invoke-webrequest"], ["curl", "invoke-webrequest"], ["wget", "invoke-webrequest"], ["irm", "invoke-restmethod"], ["iex", "invoke-expression"],
  ["sc", "set-content"], ["ac", "add-content"], ["ni", "new-item"], ["md", "new-item"], ["mkdir", "new-item"], ["echo", "write-output"], ["write", "write-output"], ["pwd", "get-location"], ["gl", "get-location"],
  ["cd", "set-location"], ["sl", "set-location"], ["chdir", "set-location"], ["%", "foreach-object"], ["foreach", "foreach-object"], ["?", "where-object"], ["where", "where-object"],
  ["select", "select-object"], ["sort", "sort-object"], ["measure", "measure-object"], ["ft", "format-table"], ["fl", "format-list"], ["gi", "get-item"], ["gp", "get-itemproperty"],
  ["sp", "set-itemproperty"], ["clc", "clear-content"], ["icm", "invoke-command"], ["saps", "start-process"], ["start", "start-process"], ["sajb", "start-job"], ["tee", "tee-object"],
  ["h", "get-history"], ["history", "get-history"], ["cls", "clear-host"], ["clear", "clear-host"], ["gcm", "get-command"], ["man", "get-help"], ["help", "get-help"], ["kill", "stop-process"], ["spps", "stop-process"], ["ps", "get-process"], ["gps", "get-process"],
]);

const READ = new Set([
  "get-childitem", "get-content", "get-item", "get-itemproperty", "test-path", "resolve-path", "select-string", "get-location", "set-location", "push-location", "pop-location",
  "measure-object", "sort-object", "select-object", "where-object", "foreach-object", "format-table", "format-list", "format-wide", "out-string", "out-host", "out-null", "write-output",
  "write-host", "write-verbose", "write-warning", "write-error", "write-information", "get-command", "get-help", "get-date", "convertfrom-json", "convertto-json", "compare-object", "split-path",
  "join-path", "get-process", "get-service", "get-history", "clear-host", "get-filehash", "get-member", "group-object", "get-unique", "convertto-csv", "convertfrom-csv", "import-csv",
  "get-alias", "get-variable", "get-psdrive", "get-module", "get-host", "get-culture", "get-random", "start-sleep", "get-acl", "get-itempropertyvalue", "test-connection_local", "get-computerinfo",
  "select-xml", "convertfrom-stringdata", "get-uptime", "get-timezone", "get-error", "out-default", "format-hex", "new-timespan", "get-filehash", "where", "tee-object_read",
]);
const WRITE = new Set(["set-content", "add-content", "out-file", "new-item", "copy-item", "move-item", "rename-item", "tee-object", "compress-archive", "expand-archive", "export-csv", "set-item", "new-variable", "set-variable", "export-clixml"]);
const NETWORK = new Set(["invoke-webrequest", "invoke-restmethod", "start-bitstransfer", "send-mailmessage", "test-netconnection", "new-pssession", "connect-pssession"]);
const PERM = new Set(["set-acl", "set-executionpolicy", "new-localuser", "add-localgroupmember", "set-localuser", "enable-psremoting", "grant-smbshareaccess"]);
const UNANALYZABLE = new Map([
  ["invoke-expression", "Invoke-Expression runs a string as code"], ["invoke-command", "Invoke-Command runs code remotely or in a script block"],
  ["enter-pssession", "Enter-PSSession opens a remote session"], ["add-type", "Add-Type compiles code"], ["start-job", "Start-Job runs code in the background"],
  ["invoke-item", "Invoke-Item opens files with their default program"], ["import-module", "Import-Module loads code"], ["new-module", "New-Module defines code at run time"],
]);
// Destructive system cmdlets (bench gap). Disk/partition wipes destroy data outright.
const DISK_WIPE = new Set(["format-volume", "clear-disk", "initialize-disk", "remove-partition", "remove-physicaldisk", "remove-virtualdisk", "remove-storagepool", "clear-recyclebin"]);
// Power and service state: irreversible for the session, so they ask.
const SYSTEM_STATE = new Set(["stop-computer", "restart-computer", "suspend-computer", "stop-service", "remove-service", "disable-computerrestore", "checkpoint-computer_off"]);
// Evidence and defence tampering.
const TAMPER = new Set(["clear-eventlog", "remove-eventlog", "limit-eventlog", "set-mppreference", "add-mppreference", "remove-mppreference", "disable-localuser", "remove-localuser", "remove-localgroupmember"]);
const STATIC_OK = /^\[(system\.)?(io\.path|math)\]::/i;

const isWordChar = (c: string) => !" \t\r\n;|&(){}<>'\"`,=".includes(c);

function tokenize(src: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  const n = src.length;
  let count = 0;
  const readBalanced = (open: string, close: string, from: number): number => {
    let depth = 0;
    for (let j = from; j < n; j++) {
      const c = src[j];
      if (c === "`") { j++; continue; }
      if (c === "'") { const e = src.indexOf("'", j + 1); if (e < 0) throw new PsUnanalyzable("unterminated string"); j = e; continue; }
      if (c === '"') { let e = j + 1; while (e < n && src[e] !== '"') { if (src[e] === "`") e++; e++; } if (e >= n) throw new PsUnanalyzable("unterminated string"); j = e; continue; }
      if (c === open) depth++;
      else if (c === close) { depth--; if (depth === 0) return j; }
    }
    throw new PsUnanalyzable(`unbalanced ${open}${close}`);
  };
  const readValueTok = (): Tok | null => {
    const save = toks.length;
    readOne();
    return toks.length > save ? (toks.pop() as Tok) : null;
  };
  function readOne(): void {
    if (++count > 4096) throw new PsUnanalyzable("too many tokens");
    const c = src[i] as string;
    // Here-strings
    if ((c === "@") && (src[i + 1] === "'" || src[i + 1] === '"') && (src[i + 2] === "\n" || (src[i + 2] === "\r" && src[i + 3] === "\n"))) {
      const q = src[i + 1] as string;
      const end = src.indexOf("\n" + q + "@", i + 2);
      if (end < 0) throw new PsUnanalyzable("unterminated here-string");
      const body = src.slice(src.indexOf("\n", i) + 1, end);
      const subs = q === '"' ? subexprs(body) : [];
      toks.push({ k: "str", v: body, dyn: q === '"' && (body.includes("$")), subs });
      i = end + 3;
      return;
    }
    if (c === "'") {
      let j = i + 1, v = "";
      for (;;) {
        if (j >= n) throw new PsUnanalyzable("unterminated string");
        if (src[j] === "'") { if (src[j + 1] === "'") { v += "'"; j += 2; continue; } break; }
        v += src[j];
        j++;
      }
      toks.push({ k: "str", v, dyn: false, subs: [] });
      i = j + 1;
      return;
    }
    if (c === '"') {
      let j = i + 1, v = "";
      for (;;) {
        if (j >= n) throw new PsUnanalyzable("unterminated string");
        if (src[j] === "`") { v += src[j + 1] ?? ""; j += 2; continue; }
        if (src[j] === '"') { if (src[j + 1] === '"') { v += '"'; j += 2; continue; } break; }
        if (src[j] === "$" && src[j + 1] === "(") { const e = readBalanced("(", ")", j + 1); v += src.slice(j, e + 1); j = e + 1; continue; }
        v += src[j];
        j++;
      }
      const subs = subexprs(v);
      toks.push({ k: "str", v, dyn: v.includes("$"), subs });
      i = j + 1;
      return;
    }
    if (c === "$" && src[i + 1] === "(") { const e = readBalanced("(", ")", i + 1); toks.push({ k: "sub", inner: src.slice(i + 2, e), array: false }); i = e + 1; return; }
    if (c === "@" && src[i + 1] === "(") { const e = readBalanced("(", ")", i + 1); toks.push({ k: "sub", inner: src.slice(i + 2, e), array: true }); i = e + 1; return; }
    if (c === "@" && src[i + 1] === "{") { const e = readBalanced("{", "}", i + 1); toks.push({ k: "hash" }); i = e + 1; return; }
    if (c === "(") { const e = readBalanced("(", ")", i); toks.push({ k: "paren", inner: src.slice(i + 1, e) }); i = e + 1; return; }
    if (c === "{") { const e = readBalanced("{", "}", i); toks.push({ k: "block", inner: src.slice(i + 1, e) }); i = e + 1; return; }
    if (c === "[" ) {
      const e = src.indexOf("]", i);
      if (e < 0) throw new PsUnanalyzable("unterminated type literal");
      let j = e + 1;
      let staticCall: string | null = null;
      if (src[j] === ":" && src[j + 1] === ":") {
        j += 2;
        while (j < n && /[A-Za-z0-9_]/.test(src[j] as string)) j++;
        staticCall = src.slice(i, j);
      }
      toks.push({ k: "type", v: src.slice(i, e + 1), staticCall });
      i = j;
      return;
    }
    // Redirections
    const redir = ["2>&1", "*>&1", "*>>", "*>", "2>>", "2>", "3>", ">>", ">", "<"].find((r) => src.startsWith(r, i));
    if (redir) {
      i += redir.length;
      while (src[i] === " " || src[i] === "\t") i++;
      if (redir.endsWith("&1") || redir === "<") { toks.push({ k: "redir", v: redir, target: null }); if (redir === "<") throw new PsUnanalyzable("'<' is reserved in PowerShell"); return; }
      const target = i < n ? readValueTok() : null;
      toks.push({ k: "redir", v: redir, target });
      return;
    }
    if (c === "-" && /[A-Za-z]/.test(src[i + 1] ?? "")) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_-]/.test(src[j] as string)) j++;
      const name = src.slice(i, j);
      if (src[j] === ":" ) { i = j + 1; const value = readValueTok(); toks.push({ k: "param", v: name, value }); return; }
      toks.push({ k: "param", v: name, value: null });
      i = j;
      return;
    }
    if (c === "$" && /[A-Za-z_{?:]/.test(src[i + 1] ?? "")) {
      let j = i + 1;
      if (src[j] === "{") { const e = src.indexOf("}", j); if (e < 0) throw new PsUnanalyzable("unterminated ${}"); j = e + 1; }
      else while (j < n && /[A-Za-z0-9_:?]/.test(src[j] as string)) j++;
      const name = src.slice(i + 1, j);
      let k = j;
      while (k < n && isWordChar(src[k] as string)) k++;
      const tail = src.slice(j, k);
      toks.push({ k: "var", name, tail });
      i = k;
      return;
    }
    // Bareword
    let j = i, v = "";
    while (j < n) {
      const ch = src[j] as string;
      if (ch === "`") { v += src[j + 1] ?? ""; j += 2; continue; }
      if (!isWordChar(ch)) break;
      v += ch;
      j++;
    }
    if (j === i) throw new PsUnanalyzable(`unexpected '${c}'`);
    toks.push({ k: "word", v, dyn: v.includes("$"), pathish: v });
    i = j;
  }
  while (i < n) {
    const c = src[i] as string;
    if (c === " " || c === "\t" || c === "\r") { i++; continue; }
    if (c === "`" && (src[i + 1] === "\n" || src[i + 1] === "\r")) { i += src[i + 1] === "\r" ? 3 : 2; continue; }
    if (c === "#") { while (i < n && src[i] !== "\n") i++; continue; }
    if (c === "<" && src[i + 1] === "#") { const e = src.indexOf("#>", i + 2); if (e < 0) throw new PsUnanalyzable("unterminated block comment"); i = e + 2; continue; }
    if (c === "\n" || c === ";") { toks.push({ k: "op", v: ";" }); i++; continue; }
    if (c === "|" && src[i + 1] === "|") { toks.push({ k: "op", v: ";" }); i += 2; continue; }
    if (c === "&" && src[i + 1] === "&") { toks.push({ k: "op", v: ";" }); i += 2; continue; }
    if (c === "|") { toks.push({ k: "op", v: "|" }); i++; continue; }
    if (c === "&") { toks.push({ k: "op", v: "&" }); i++; continue; }
    if (c === "=" ) { toks.push({ k: "op", v: "=" }); i++; continue; }
    if (c === ",") { i++; continue; }
    if (c === "." && (src[i + 1] === " " || src[i + 1] === "\t") && (toks.length === 0 || toks[toks.length - 1]?.k === "op")) { toks.push({ k: "op", v: "." }); i++; continue; }
    if (c === "+" && (src[i + 1] === " " || src[i + 1] === "=")) { i += src[i + 1] === "=" ? 2 : 1; continue; }
    readOne();
  }
  return toks;
}

/** Subexpressions $( … ) inside an expandable string. */
function subexprs(s: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "$" && s[i + 1] === "(") {
      let depth = 0;
      for (let j = i + 1; j < s.length; j++) {
        if (s[j] === "(") depth++;
        else if (s[j] === ")") { depth--; if (depth === 0) { out.push(s.slice(i + 2, j)); i = j; break; } }
      }
    }
  }
  return out;
}

export interface PsState { pctx: PathCtx; depth: number; maxBytes: number }

export function analyzePowerShell(src: string, st: PsState): Acc {
  const acc = new Acc();
  if (src.length > st.maxBytes) { acc.unanalyzable("command longer than the analysis limit"); return acc; }
  if (st.depth > 3) { acc.unanalyzable("PowerShell nested too deep"); return acc; }
  let toks: Tok[];
  try {
    toks = tokenize(src);
  } catch (e) {
    acc.unanalyzable(e instanceof PsUnanalyzable ? e.reason : "PowerShell parse error");
    return acc;
  }
  // Split into statements and pipeline elements.
  const cwd = { cwd: st.pctx.cwd };
  let element: Tok[] = [];
  let upstream: Tok[] | null = null; // the previous element when the current one is piped into
  let pipedNext = false;
  const flush = (sep: string) => {
    if (element.length) analyzeElement(element, st, acc, cwd, pipedNext ? upstream : null);
    upstream = element.length ? element : null;
    pipedNext = sep === "|";
    element = [];
  };
  for (const t of toks) {
    if (t.k === "op" && (t.v === ";" || t.v === "|")) { flush(t.v); continue; }
    element.push(t);
  }
  flush(";");
  // Same correlation as bash: a sensitive file and a network call in one command.
  if (acc.network && (acc.sensitiveArgs || acc.envDump)) acc.find("CP-EXFIL-030", "sensitive file or environment and a network call in one command");
  return acc;
}

function inner(src: string, st: PsState, acc: Acc, commandPosition: boolean, allowWrite: boolean): void {
  const a = analyzePowerShell(src, { ...st, depth: st.depth + 1 });
  if (a.selfProtection) { acc.selfProtection = true; acc.tags.add("self-protection"); for (const f of a.findings) if (f.ruleId.startsWith("CP-SELF")) acc.find(f.ruleId, f.note); acc.raise("high-risk"); }
  if (commandPosition) { acc.unanalyzable("command name comes from a subexpression"); return; }
  if (a.unanalyzableFlag) { acc.unanalyzable("subexpression contains an unanalyzable command"); return; }
  if (a.level === "high-risk" || a.sensitive.length > 0) { for (const t of a.tags) acc.tags.add(t); acc.unanalyzable("subexpression runs a dangerous command"); return; }
  if (a.tags.has("exec.unknown") || a.tags.has("exec.project-code") || a.tags.has("exec.inline-code")) { acc.unanalyzable("subexpression runs an unknown command"); return; }
  if (a.level === "write-reversible") { if (!allowWrite) acc.raise("write-reversible"); for (const t of a.tags) acc.tags.add(t); }
}

/**
 * A recursive delete of this path destroys data a user can't easily get back: a drive or
 * filesystem root, the home directory, everything in it (home/*), or a folder directly under it
 * (Documents, Desktop, .ssh, a whole project). Deeper paths (node_modules, dist) don't count.
 */
function destroysTopLevel(path: string | null, pctx: PathCtx): boolean {
  if (path === null) return false;
  const home = normalizePath("~", pctx).path ?? "";
  const lp = path.toLowerCase(), lh = home.toLowerCase();
  if (/^[a-z]:\/?\*?$/i.test(path) || path === "/" || path === "/*") return true;
  if (lh !== "" && (lp === lh || lp === lh + "/")) return true;
  return homeTopLevel(path, pctx);
}

function tokText(t: Tok | null | undefined): { value: string | null; pathValue: string | null } {
  if (!t) return { value: null, pathValue: null };
  if (t.k === "str") return { value: t.dyn ? null : t.v, pathValue: t.dyn ? (/^\$env:USERPROFILE|^\$HOME/i.test(t.v) && !t.v.includes("$(") ? t.v : null) : t.v };
  if (t.k === "word") return { value: t.dyn ? null : t.v, pathValue: t.v };
  if (t.k === "var") {
    const full = "$" + t.name + t.tail;
    const homeish = /^(env:USERPROFILE|HOME)$/i.test(t.name);
    return { value: null, pathValue: homeish ? full : null };
  }
  return { value: null, pathValue: null };
}

function wi(t: Tok): WordInfo {
  const { value, pathValue } = tokText(t);
  const word: Word = value !== null ? litWord(value) : { parts: [{ t: "var", name: "X", braced: false, quoted: false }], raw: t.k === "word" ? t.v : t.k === "str" ? t.v : "$x", brace: false };
  return { word, value, pathValue, suffix: "", dynamic: value === null, glob: false, substs: [] };
}

function np(t: Tok | null | undefined, pctx: PathCtx): NormPath | null {
  const { pathValue } = tokText(t);
  return pathValue === null ? null : normalizePath(pathValue, pctx);
}

function hasParam(params: Tok[], full: string): boolean {
  const f = full.toLowerCase();
  return params.some((p) => p.k === "param" && p.v.length >= 2 && f.startsWith(p.v.toLowerCase()));
}

function paramValue(el: Tok[], ...names: string[]): Tok | null {
  for (let i = 0; i < el.length; i++) {
    const t = el[i] as Tok;
    if (t.k !== "param") continue;
    const lower = t.v.toLowerCase();
    if (names.some((n) => n.toLowerCase().startsWith(lower) && lower.length >= 3)) return t.value ?? el[i + 1] ?? null;
  }
  return null;
}

function positional(el: Tok[]): Tok[] {
  const out: Tok[] = [];
  const switches = new Set(["-recurse", "-force", "-whatif", "-confirm", "-verbose", "-passthru", "-nonewline", "-append", "-raw", "-wait", "-file", "-directory", "-hidden", "-r", "-fo", "-rec", "-literalpath_s"]);
  for (let i = 1; i < el.length; i++) {
    const t = el[i] as Tok;
    if (t.k === "param") {
      if (t.value === null && !switches.has(t.v.toLowerCase()) && !t.v.toLowerCase().startsWith("-rec") && el[i + 1] && el[i + 1]?.k !== "param") i++;
      continue;
    }
    if (t.k === "redir" || t.k === "op") continue;
    out.push(t);
  }
  return out;
}

function analyzeElement(el: Tok[], st: PsState, acc: Acc, cwd: { cwd: string | null }, upstream: Tok[] | null = null): void {
  const pctx: PathCtx = { ...st.pctx, cwd: cwd.cwd };
  // Destinations of copy/move/write cmdlets are writes, not sensitive reads.
  const head0 = el[0];
  const name0 = head0?.k === "word" ? head0.v.toLowerCase() : "";
  const cmd0 = ALIASES.get(name0) ?? name0;
  const writeDest = new Set<Tok>();
  if (["copy-item", "move-item", "set-content", "add-content", "out-file", "new-item", "rename-item", "tee-object"].includes(cmd0)) {
    const pos0 = positional(el);
    const last = cmd0 === "copy-item" || cmd0 === "move-item" ? pos0[pos0.length - 1] : pos0[0];
    if (last) writeDest.add(last);
    const dest = paramValue(el, "-Destination");
    if (dest) writeDest.add(dest);
  }
  // Nested pieces anywhere in the element.
  el.forEach((t, idx) => {
    if (t.k === "sub") inner(t.inner, st, acc, idx === 0 || (idx === 1 && el[0]?.k === "op"), true);
    if (t.k === "str") for (const s of t.subs) inner(s, st, acc, false, true);
    if (t.k === "paren" && idx > 0) inner(t.inner, st, acc, false, true);
    if (t.k === "block" && idx > 0) { const a = analyzePowerShell(t.inner, { ...st, depth: st.depth + 1 }); acc.merge(a); }
    if (t.k === "type" && t.staticCall && !STATIC_OK.test(t.staticCall)) acc.unanalyzable(`static .NET call ${t.staticCall.slice(0, 60)}`);
    if (t.k === "redir" && t.target) {
      const p = np(t.target, pctx);
      if (p === null) { acc.unanalyzable("redirects to a path that isn't known statically"); return; }
      if (isProtected(p, pctx) || isProtectedRead(p, pctx)) acc.protect("CP-SELF-001", "writes a file that controls the agent or Glassbox");
      acc.tag("write-reversible", "fs.write");
    }
    if (t.k === "word" || t.k === "str" || t.k === "var") {
      const p = np(t, pctx);
      if (p && (t.k !== "word" || /[\\/~.]/.test(t.v))) {
        if (isProtectedRead(p, pctx)) acc.protect("CP-SELF-002", "reads a Glassbox credential file");
        const label = idx > 0 && !writeDest.has(t) ? sensitiveLabel(p, pctx) : null;
        if (label && !acc.selfProtection) { acc.tags.add("fs.read.sensitive"); acc.sensitive.push(label); acc.sensitiveArgs = true; acc.find("CP-EXFIL-040", label); }
      }
    }
  });
  let head = el[0];
  if (!head) return;
  // Assignment: $x = …
  if (head.k === "var" && el[1]?.k === "op" && el[1].v === "=") {
    const name = head.name.toLowerCase();
    if (["env:path", "env:psmodulepath", "profile", "env:pathext", "env:comspec", "psdefaultparametervalues", "executioncontext"].includes(name)) acc.unanalyzable(`assignment to $${head.name} changes what later commands run`);
    const rhs = el.slice(2);
    if (rhs[0]?.k === "word" || (rhs[0]?.k === "op" && rhs[0].v === "&")) analyzeElement(rhs, st, acc, cwd);
    return;
  }
  // Call operators.
  let callOp = false;
  if (head.k === "op" && (head.v === "&" || head.v === ".")) {
    callOp = true;
    const target = el[1];
    const { value } = tokText(target);
    if (!target || value === null) { acc.unanalyzable(`'${head.v}' with a non-literal target`); return; }
    el = [{ k: "word", v: value, dyn: false, pathish: value }, ...el.slice(2)];
    head = el[0] as Tok;
  }
  if (head.k !== "word") {
    // Expression statement (string, variable, number, paren…): only its pieces matter.
    if (head.k === "block") acc.merge(analyzePowerShell(head.inner, { ...st, depth: st.depth + 1 }));
    if (head.k === "paren") inner(head.inner, st, acc, false, false);
    return;
  }
  if (head.dyn) { acc.unanalyzable("command name isn't literal"); return; }
  const name = head.v.toLowerCase().replace(/\.exe$/, "");
  const base = name.includes("\\") || name.includes("/") ? (name.split(/[\\/]/).pop() ?? name) : name;
  const cmdlet = ALIASES.get(base) ?? base;
  const params = el.filter((t) => t.k === "param");
  const pos = positional(el);

  const reason = UNANALYZABLE.get(cmdlet);
  if (reason) { acc.unanalyzable(reason); return; }
  if (cmdlet === "start-process") {
    const file = paramValue(el, "-FilePath") ?? pos[0];
    const args = paramValue(el, "-ArgumentList");
    if (!file || tokText(file).value === null || (args && tokText(args).value === null)) { acc.unanalyzable("Start-Process with a non-literal program or arguments"); return; }
    if (params.some((p) => p.k === "param" && p.v.toLowerCase().startsWith("-verb")) && el.some((t) => (t.k === "word" || t.k === "str") && /^runas$/i.test(t.v))) acc.tag("high-risk", "perm.change");
    acc.tag("write-reversible", "exec.unknown");
    return;
  }
  if (base === "powershell" || base === "pwsh") {
    if (params.some((p) => p.k === "param" && /^-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)$/i.test(p.v))) { acc.unanalyzable("encoded PowerShell command"); return; }
    const cmd = paramValue(el, "-Command");
    if (cmd) {
      const { value } = tokText(cmd);
      if (value === null) { acc.unanalyzable("PowerShell -Command with a non-literal command"); return; }
      acc.merge(analyzePowerShell(value, { ...st, depth: st.depth + 1 }));
      return;
    }
    if (paramValue(el, "-File")) { acc.tag("write-reversible", "exec.project-code"); return; }
    acc.unanalyzable("nested PowerShell reads commands it can't see");
    return;
  }
  if (base === "cmd") { acc.unanalyzable("cmd.exe syntax isn't analyzed"); return; }

  const pathTargets = (): (Tok | null)[] => {
    const named = [paramValue(el, "-Path"), paramValue(el, "-LiteralPath"), paramValue(el, "-Destination"), paramValue(el, "-FilePath"), paramValue(el, "-OutFile")].filter((x) => x !== null);
    return [...named, ...pos.filter((t) => t.k !== "block")];
  };
  const isRegistry = (t: Tok | null) => /^(hk(lm|cu|cr|u|cc):|registry::)/i.test(tokText(t).pathValue ?? "");
  const policyKey = (t: Tok | null) => (tokText(t).pathValue ?? "").toLowerCase().replace(/[\\/]/g, "").includes("policiesclaudecode");

  if (READ.has(cmdlet)) {
    if (cmdlet === "set-location") {
      const t = pos[0] ?? paramValue(el, "-Path");
      const p = np(t, pctx);
      cwd.cwd = p?.path ?? null;
    }
    if (cmdlet === "get-itemproperty" && pathTargets().some(policyKey)) return;
    return;
  }
  if (["set-itemproperty", "new-itemproperty", "remove-itemproperty", "clear-itemproperty", "rename-itemproperty"].includes(cmdlet) || ((cmdlet === "new-item" || cmdlet === "remove-item" || cmdlet === "set-item") && pathTargets().some(isRegistry))) {
    if (pathTargets().some(policyKey)) { acc.protect("CP-SELF-003", "changes Claude Code policy in the registry"); return; }
    acc.tag("high-risk", "config.agent");
    acc.reason("changes the Windows registry");
    return;
  }
  if (cmdlet === "remove-item" || cmdlet === "clear-content" || cmdlet === "clear-item") {
    acc.tag("high-risk", "fs.delete");
    let recurse = hasParam(params, "-Recurse");
    let targets = pathTargets();
    let narrowed = false;
    if (targets.length === 0 && upstream) {
      // `Get-ChildItem <path> [-Recurse] | Remove-Item`: the items come from the upstream path.
      const up = upstream[0];
      const upName = up?.k === "word" ? (ALIASES.get(up.v.toLowerCase()) ?? up.v.toLowerCase()) : "";
      if (upName !== "get-childitem" && upName !== "get-item") { acc.unanalyzable("deletes whatever an earlier pipeline stage produces"); return; }
      const upParams = upstream.filter((t) => t.k === "param");
      const upTargets = [paramValue(upstream, "-Path"), paramValue(upstream, "-LiteralPath"), ...positional(upstream)].filter((x) => x !== null);
      // A filter or a wildcard narrows what is deleted: not a whole-folder delete.
      narrowed = hasParam(upParams, "-Filter") || hasParam(upParams, "-Include") || upTargets.some((t) => /[*?]/.test(tokText(t).pathValue ?? ""));
      targets = upTargets.length > 0 ? upTargets : [{ k: "word", v: ".", dyn: false, pathish: "." }];
      recurse ||= hasParam(upParams, "-Recurse");
    }
    for (const t of targets) {
      const p = np(t, pctx);
      if (p === null) { acc.unanalyzable("deletes a path that isn't known statically"); continue; }
      if (isProtectedWrite(p, pctx, /[*?[]/.test(p.path ?? ""))) acc.protect("CP-SELF-001", "deletes a file that controls the agent or Glassbox");
      acc.persist(persistenceHit(p, pctx), "deletes", p.path);
      acc.wrote(p.path);
      if (recurse && !narrowed && destroysTopLevel(p.path, pctx)) { acc.tag("high-risk", "fs.destroy"); acc.find("CP-ACTION-001", "deletes a whole drive, the home directory or a top-level folder in it"); }
    }
    return;
  }
  // Scheduled tasks and services (rev 9): ask with the schedule and the command (CP-SELF-006).
  // Register-ScheduledTask's action and trigger are usually built earlier in the script; the
  // gate reads them from the whole command (psTaskJob).
  if (cmdlet === "register-scheduledtask" || cmdlet === "register-scheduledjob" || cmdlet === "set-scheduledtask") {
    acc.scheduleJob({ kind: "task-scheduler", verb: cmdlet === "set-scheduledtask" ? "changes" : "creates", path: null, schedule: null, files: [] });
    return;
  }
  if (cmdlet === "unregister-scheduledtask" || cmdlet === "unregister-scheduledjob") {
    acc.scheduleJob({ kind: "task-scheduler", verb: "removes", path: null, schedule: null, files: [] });
    return;
  }
  if (cmdlet === "new-service" || cmdlet === "set-service" && hasParam(params, "-StartupType")) {
    const bin = paramValue(el, "-BinaryPathName");
    const start = paramValue(el, "-StartupType");
    const binText = bin ? tokText(bin).value : null;
    acc.scheduleJob({ kind: "service", verb: cmdlet === "new-service" ? "creates" : "changes", path: null, schedule: start ? `startup type ${tokText(start).value ?? "?"}` : "as a Windows service", files: binText ? commandFiles(binText) : [] });
    return;
  }
  if (cmdlet === "clear-history" || (cmdlet === "set-psreadlineoption" && (hasParam(params, "-AddToHistoryHandler") || /savenothing/i.test(el.map((t) => tokText(t).value ?? "").join(" "))))) {
    acc.tag("high-risk", "fs.delete");
    acc.find("CP-ACTION-030", `${cmdlet} clears or stops PowerShell history`);
    return;
  }
  if (DISK_WIPE.has(cmdlet)) { acc.tag("high-risk", "fs.destroy"); acc.find("CP-ACTION-001", `${cmdlet} erases a disk, partition or the recycle bin`); return; }
  if (SYSTEM_STATE.has(cmdlet)) { acc.tag("high-risk", "infra.change"); acc.reason(`${cmdlet} changes the machine's power or service state`); return; }
  if (TAMPER.has(cmdlet)) { acc.tag("high-risk", "perm.change"); acc.reason(`${cmdlet} changes logs, Defender settings or accounts`); return; }
  if (WRITE.has(cmdlet)) {
    acc.tag("write-reversible", cmdlet === "move-item" || cmdlet === "rename-item" ? "fs.move" : "fs.write");
    const targets = pathTargets();
    const writeTargets = cmdlet === "copy-item" || cmdlet === "move-item" ? (paramValue(el, "-Destination") ? [paramValue(el, "-Destination")] : targets.slice(-1)) : targets.slice(0, cmdlet === "set-content" || cmdlet === "add-content" ? 1 : targets.length);
    for (const t of [...writeTargets, ...(cmdlet === "move-item" || cmdlet === "rename-item" ? targets : [])]) {
      const p = np(t, pctx);
      if (p === null) { acc.unanalyzable("writes a path that isn't known statically"); continue; }
      if (isProtectedWrite(p, pctx, /[*?[]/.test(p.path ?? ""))) acc.protect("CP-SELF-001", "changes a file that controls the agent or Glassbox");
      acc.persist(persistenceHit(p, pctx), "changes", p.path);
      acc.wrote(p.path);
      const lp = (p.path ?? "").toLowerCase();
      if (lp.endsWith("profile.ps1") || lp.includes("/.git/hooks/")) acc.tag("high-risk", "config.agent");
    }
    return;
  }
  if (NETWORK.has(cmdlet)) {
    const dest = paramValue(el, "-Uri") ?? paramValue(el, "-SmtpServer") ?? (cmdlet === "send-mailmessage" ? null : positional(el)[0] ?? null);
    const loop = allLoopback(dest ? [tokText(dest).value] : []);
    if (!loop) { acc.tag("high-risk", "net.egress"); acc.network = true; }
    // Uploads: -InFile, and -Attachments (comma-separated).
    const files: (string | null)[] = [];
    const inFile = paramValue(el, "-InFile");
    if (inFile) files.push(tokText(inFile).pathValue);
    const att = paramValue(el, "-Attachments");
    if (att) { const v = tokText(att).pathValue; if (v === null) files.push(null); else files.push(...v.split(",").map((x) => x.trim()).filter(Boolean)); }
    if (cmdlet === "send-mailmessage") {
      // Further positional words after -Attachments a, b are more attachments.
      const i = el.findIndex((t) => t.k === "param" && t.v.toLowerCase() === "-attachments");
      for (let k = i + 2; i >= 0 && k < el.length && el[k]?.k !== "param"; k++) { const t = tokText(el[k]); if (t.pathValue !== null && t.pathValue !== ",") files.push(t.pathValue.replace(/^,|,$/g, "")); }
    }
    if (!loop) {
      for (const f of files) {
        const p = f === null ? null : np({ k: "word", v: f, dyn: false } as Tok, pctx);
        recordUpload(acc, classifyUpload(p, pctx, st.pctx.cwd, f), f ?? "a file named at run time");
      }
    }
    return;
  }
  if (PERM.has(cmdlet)) { acc.tag("high-risk", "perm.change"); return; }
  if (cmdlet === "new-object") {
    if (el.some((t) => (t.k === "word" || t.k === "str") && /net\.(webclient|sockets)|system\.net/i.test(t.v))) { acc.tag("high-risk", "net.egress"); acc.network = true; return; }
    acc.unanalyzable("New-Object creates arbitrary .NET objects");
    return;
  }
  if (cmdlet === "stop-process") { acc.tag("write-reversible", "exec.unknown"); return; }
  if (/^[a-z]+-[a-z]+$/.test(cmdlet) && !callOp) { acc.tag("write-reversible", "exec.unknown"); acc.reason(`runs the cmdlet ${cmdlet.slice(0, 40)}`); return; }

  // Native program: same rules as the bash command table.
  const args = el.slice(1).filter((t) => t.k !== "redir").map((t) => (t.k === "param" ? wi({ k: "word", v: t.v, dyn: false, pathish: t.v }) : wi(t)));
  const fake: SimpleCommand = { kind: "simple", assigns: [], words: [litWord(base)], redirects: [], pipedIn: false, pipedFrom: null };
  classifyNative(base, args, fake, { pctx, depth: st.depth, maxBytes: st.maxBytes }, acc, cwd);
}
