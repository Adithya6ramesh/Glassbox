// Tool classification: built-in agent tools and MCP tools.
import type { ActionTag, ToolDef } from "../types.js";
import { get, getString, isRecord } from "../util/misc.js";
import { Acc } from "./acc.js";
import {
  coversProtectedRead, globCoversProtectedRead, isProtected, isProtectedRead, normalizePath, persistenceHit, sensitiveLabel, type PathCtx,
} from "./paths.js";
import { builtinCategory } from "./builtin-tools.js";
import { analyzePowerShell } from "./powershell.js";
import { isProtectedWrite } from "./protected-write.js";
import { analyzeShellCommand } from "./shell/analyze.js";
import { analyzeSql } from "./sql.js";

export interface ToolCtx { pctx: PathCtx; maxCommandBytes: number; maxSqlBytes: number }

const READ_TOOLS = new Set(["read", "glob", "grep", "ls", "lsp", "websearch", "todowrite", "todoread", "askuserquestion", "exitplanmode", "notebookread", "bashoutput", "taskoutput", "listmcpresourcestool", "readmcpresourcetool", "toolsearch"]);
const WRITE_TOOLS = new Set(["write", "edit", "multiedit", "notebookedit"]);

export function writePath(path: string, acc: Acc, t: ToolCtx): void {
  const np = normalizePath(path, t.pctx);
  if (isProtectedWrite(np, t.pctx)) acc.protect("CP-SELF-001", "changes a file that controls the agent or Glassbox");
  acc.persist(persistenceHit(np, t.pctx), "changes", np.path);
  acc.wrote(np.path);
  const p = (np.path ?? np.suffix ?? "").toLowerCase();
  if (p.includes("/.git/hooks/") || p.endsWith("/.git/config") || p.includes("/.husky/") || p.endsWith("/.envrc") || p.endsWith("/.bashrc") || p.endsWith("/.zshrc") || p.endsWith("/.profile") || p.endsWith("/.bash_profile") || p.endsWith("/.pre-commit-config.yaml") || p.endsWith("profile.ps1") || p.includes("/library/launchagents/") || p.includes("/.config/systemd/user/")) {
    acc.tag("high-risk", "config.agent");
    acc.reason("writes a file that runs commands later");
  }
}

function readPath(path: string, acc: Acc, t: ToolCtx, recursive: boolean): void {
  const np = normalizePath(path, t.pctx);
  if (recursive ? coversProtectedRead(np, t.pctx) : isProtectedRead(np, t.pctx)) { acc.protect("CP-SELF-002", "reads a Glassbox credential file"); return; }
  const label = sensitiveLabel(np, t.pctx);
  if (label) {
    acc.tags.add("fs.read.sensitive");
    acc.sensitive.push(label);
    acc.sensitiveArgs = true;
    acc.find("CP-EXFIL-040", label);
    acc.reason(`reads a sensitive file (${label})`);
  }
}

export function hostOf(url: string): string | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#@\s]*@)?(\[[^\]]*\]|[^/?#:\s]+)/i.exec(url.slice(0, 2048));
  return m ? (m[2] as string).toLowerCase() : null;
}

export function classifyBuiltin(toolName: string, args: unknown, t: ToolCtx): Acc {
  const acc = new Acc();
  const name = toolName.toLowerCase();
  const str = (k: string) => getString(args, k);
  if (name === "bash") {
    const cmd = str("command");
    if (cmd === undefined) { acc.unanalyzable("Bash call without a command string"); return acc; }
    return analyzeShellCommand(cmd, { pctx: t.pctx, depth: 0, maxBytes: t.maxCommandBytes });
  }
  if (name === "powershell") {
    const cmd = str("command");
    if (cmd === undefined) { acc.unanalyzable("PowerShell call without a command string"); return acc; }
    return analyzePowerShell(cmd, { pctx: t.pctx, depth: 0, maxBytes: t.maxCommandBytes });
  }
  if (WRITE_TOOLS.has(name)) {
    acc.tag("write-reversible", "fs.write");
    const p = str("file_path") ?? str("notebook_path") ?? str("path");
    if (p === undefined) { acc.unanalyzable("write tool without a file path"); return acc; }
    writePath(p, acc, t);
    return acc;
  }
  if (name === "monitor") {
    // Monitor runs a background shell command (or watches a WebSocket) and streams its output
    // to the agent. The command gets the full shell analysis, like Bash.
    const cmd = str("command");
    let out: Acc | null = cmd !== undefined ? analyzeShellCommand(cmd, { pctx: t.pctx, depth: 0, maxBytes: t.maxCommandBytes }) : null;
    const wsUrl = getString(get(args, "ws"), "url");
    if (wsUrl !== undefined) {
      const a = out ?? acc;
      a.tag("high-risk", "net.egress");
      a.network = true;
      const h = hostOf(wsUrl);
      a.reason(h ? `watches a WebSocket on ${h}` : "watches a WebSocket on an unknown host");
      out = a;
    }
    if (out === null) { acc.unanalyzable("Monitor call without a command string"); return acc; }
    return out;
  }
  if (name === "webfetch") {
    acc.tag("high-risk", "net.egress");
    acc.network = true;
    const h = hostOf(str("url") ?? "");
    acc.reason(h ? `destination host: ${h}` : "destination host unknown");
    return acc;
  }
  if (name === "enterworktree") {
    acc.tag("write-reversible", "fs.write");
    const p = str("path");
    if (p !== undefined) writePath(p, acc, t);
    acc.reason("creates or enters a git worktree");
    return acc;
  }
  if (name === "exitworktree") {
    acc.tag("write-reversible", "fs.write");
    acc.reason("leaves a git worktree");
    return acc;
  }
  if (READ_TOOLS.has(name)) {
    if (name === "read" || name === "notebookread" || name === "lsp") {
      const p = str("file_path") ?? str("filePath") ?? str("path") ?? str("notebook_path");
      if (p !== undefined) readPath(p, acc, t, false);
    }
    if (name === "grep") {
      const p = str("path") ?? (t.pctx.cwd ?? ".");
      readPath(p, acc, t, true);
      const g = str("glob");
      if (g && globCoversProtectedRead(g, p, t.pctx)) acc.protect("CP-SELF-002", "searches Glassbox credential files");
    }
    if (name === "glob") {
      const pattern = str("pattern") ?? "";
      if (globCoversProtectedRead(pattern, str("path") ?? null, t.pctx)) acc.protect("CP-SELF-002", "lists Glassbox credential files");
    }
    return acc;
  }
  const label = toolName.slice(0, 40);
  switch (builtinCategory(toolName)) {
    case "network":
      // Artifact, ShareOnboardingGuide: publish local content to a hosted page.
      acc.tag("high-risk", "net.egress");
      acc.network = true;
      acc.reason(`sends content off the machine (${label})`);
      return acc;
    case "agent":
      if (name === "remotetrigger") {
        acc.tag("high-risk", "exec.nested-agent");
        acc.reason("creates or runs a scheduled agent in the cloud, where these checks don't run");
        return acc;
      }
      // Agent, Workflow, Skill, SendMessage, CronCreate, ScheduleWakeup: the work they start runs
      // as ordinary tool calls in this Claude Code, and each of those is checked.
      acc.raise("write-reversible");
      acc.reason(`starts agent work (${label}); its tool calls are checked one by one`);
      return acc;
    case "other":
      acc.raise("write-reversible");
      acc.reason(`acts inside the session (${label})`);
      return acc;
    case "read":
      return acc;
    case "command":
    case "write":
    case undefined:
      break;
  }
  // A built-in tool this engine doesn't know: it may run commands or write files, and nothing
  // here can tell. Unanalyzable (ask; deny in autopilot), never "harmless".
  acc.unanalyzable(`unknown agent tool ${label}`);
  return acc;
}

// ── MCP tools ────────────────────────────────────────────────────────────

const HIGH_VERBS = new Set(["delete", "remove", "destroy", "drop", "truncate", "deploy", "publish", "post", "send", "transfer", "pay", "refund", "charge", "merge", "push", "grant", "revoke", "invite", "archive", "execute", "exec", "run", "purge", "wipe", "kill", "terminate", "erase", "unpublish", "release", "approve", "submit", "tweet", "email", "notify", "broadcast", "withdraw", "sell", "buy", "order", "book", "cancel", "reset", "overwrite", "shutdown", "restart", "reboot", "ban", "kick", "suspend", "disable", "uninstall"]);
const WRITE_VERBS = new Set(["create", "update", "set", "add", "edit", "write", "upload", "modify", "put", "patch", "save", "insert", "rename", "move", "copy", "upsert", "append", "make", "new", "change", "assign", "label", "tag", "comment", "reply", "star", "fork", "open", "close", "enable", "install", "configure", "register", "import", "sync", "store", "commit", "mark", "pin", "schedule", "generate", "build", "convert", "format", "translate"]);
const READ_VERBS = new Set(["get", "list", "read", "search", "fetch", "query", "describe", "show", "find", "view", "count", "lookup", "check", "status", "retrieve", "download", "browse", "inspect", "explain", "summarize", "analyze", "lint", "validate", "preview", "diff", "compare", "resolve", "info", "whoami", "ping", "echo", "calculate", "compute", "time", "weather", "forecast", "now"]);

export function nameWords(name: string): string[] {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function verbTags(words: string[]): ActionTag[] {
  const has = (...xs: string[]) => xs.some((x) => words.includes(x));
  const tags: ActionTag[] = [];
  if (has("send", "email", "notify", "broadcast", "tweet", "dm") && has("email", "mail", "message", "messages", "sms", "slack", "chat", "notification", "tweet", "dm", "text", "post")) tags.push("message.send");
  if (has("transfer", "pay", "refund", "charge", "payment", "invoice", "withdraw", "payout", "sell", "buy", "order")) tags.push("payment");
  if (has("publish", "post", "tweet", "release", "unpublish")) tags.push("publish.public");
  if (has("deploy")) tags.push(has("prod", "production") ? "deploy.prod" : "deploy.other");
  if (has("merge", "push")) tags.push("vcs.push");
  if (has("grant", "revoke", "invite", "ban", "kick", "suspend")) tags.push("perm.change");
  if (has("delete", "remove", "destroy", "drop", "truncate", "purge", "wipe", "erase", "archive", "overwrite")) tags.push(has("table", "database", "db", "row", "rows", "record", "records", "collection") ? "db.delete" : "fs.delete");
  if (has("execute", "exec", "run", "kill", "terminate", "shutdown", "restart", "reboot")) tags.push("exec.unknown");
  return tags;
}

export interface McpProfile { acc: Acc; contradiction: boolean }

/** Vocabulary + annotation profile of an MCP tool (no arguments). */
export function profileMcpTool(name: string, descriptor: ToolDef | undefined): McpProfile {
  const acc = new Acc();
  const desc = typeof descriptor?.description === "string" ? descriptor.description : "";
  const firstSentence = desc.split(/[.\n]/)[0]?.slice(0, 300) ?? "";
  const words = nameWords(name);
  const descWords = nameWords(firstSentence).slice(0, 3);
  const all = [...words, ...descWords];
  // Tool names are verb-first (get_release_by_tag): after a read or write verb, a "high" word is
  // a noun. A high verb counts when it leads the name, or when the name has no read/write verb.
  const plainVerb = words.some((w) => READ_VERBS.has(w) || WRITE_VERBS.has(w));
  const high = HIGH_VERBS.has(words[0] ?? "") || (!plainVerb && words.some((w) => HIGH_VERBS.has(w))) || (words.length > 0 && !plainVerb && descWords.some((w) => HIGH_VERBS.has(w)));
  const write = all.some((w) => WRITE_VERBS.has(w));
  const read = words.some((w) => READ_VERBS.has(w)) || (!high && !write && descWords.some((w) => READ_VERBS.has(w)));
  if (high) { acc.raise("high-risk"); const tags = verbTags(all); for (const tg of tags) acc.tags.add(tg); if (tags.length === 0) acc.tags.add("exec.unknown"); }
  else if (write) acc.tag("write-reversible", "fs.write");
  else if (read) acc.raise("read");
  else acc.tag("write-reversible", "exec.unknown");
  const ann = isRecord(descriptor?.annotations) ? descriptor?.annotations : undefined;
  let contradiction = false;
  if (ann && get(ann, "destructiveHint") === true) { acc.raise("high-risk"); if (acc.tags.size === 0) acc.tags.add("fs.delete"); }
  if (ann && get(ann, "readOnlyHint") === true && high) contradiction = true;
  if (ann && get(ann, "openWorldHint") === true && acc.level !== "read") acc.tags.add("net.egress");
  return { acc, contradiction };
}

const COMMAND_KEYS = new Set(["command", "cmd", "script", "shell", "bash", "commandline", "command_line"]);
const SQL_KEYS = new Set(["sql", "query", "statement", "stmt", "q"]);
const PATH_KEYS = new Set(["path", "file", "filename", "file_path", "filepath", "target", "destination", "dest", "dir", "directory", "output", "outfile", "output_path"]);

export function classifyMcp(name: string, args: unknown, descriptor: ToolDef | undefined, t: ToolCtx): McpProfile {
  const prof = profileMcpTool(name, descriptor);
  const acc = prof.acc;
  const words = nameWords(name);
  const sqlLike = words.some((w) => ["sql", "query", "execute", "exec", "db", "database", "postgres", "mysql", "sqlite", "select"].includes(w));
  const isRead = acc.level === "read";
  if (!isRecord(args)) return prof;
  let sqlSeen = false;
  const sqlAcc = new Acc();
  for (const k of Object.keys(args)) {
    const v = args[k];
    if (typeof v !== "string") continue;
    const key = k.toLowerCase();
    if (COMMAND_KEYS.has(key)) acc.merge(analyzeShellCommand(v, { pctx: t.pctx, depth: 0, maxBytes: t.maxCommandBytes }));
    if (SQL_KEYS.has(key) && sqlLike) { sqlSeen = true; sqlAcc.merge(analyzeSql(v, t.maxSqlBytes)); }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v.slice(0, 20)) && /^https?:|^wss?:|^ftp:/i.test(v) && !isRead) { acc.tag("high-risk", "net.egress"); acc.network = true; }
    if (PATH_KEYS.has(key)) {
      const np = normalizePath(v, t.pctx);
      if (isProtectedRead(np, t.pctx)) acc.protect("CP-SELF-002", "reads a Glassbox credential file");
      else if (!isRead && isProtected(np, t.pctx)) acc.protect("CP-SELF-001", "changes a file that controls the agent or Glassbox");
      else if (!isRead && persistenceHit(np, t.pctx)) acc.persist(persistenceHit(np, t.pctx), "changes", np.path);
      if (!isRead) acc.wrote(np.path);
      else if (isRead) { const label = sensitiveLabel(np, t.pctx); if (label) { acc.tags.add("fs.read.sensitive"); acc.sensitive.push(label); acc.sensitiveArgs = true; acc.find("CP-EXFIL-040", label); } }
    }
  }
  if (sqlSeen) {
    // The statement decides, not the tool's verb.
    const keep = new Acc();
    keep.merge(sqlAcc);
    for (const f of acc.findings) keep.find(f.ruleId, f.note);
    if (acc.selfProtection) keep.selfProtection = true;
    for (const tg of acc.tags) if (tg === "net.egress" || tg === "self-protection") keep.tags.add(tg);
    for (const r of acc.unanalyzableReasons) keep.unanalyzable(r);
    const ann = isRecord(descriptor?.annotations) ? descriptor?.annotations : undefined;
    if (ann && get(ann, "destructiveHint") === true) keep.raise("high-risk");
    return { acc: keep, contradiction: prof.contradiction };
  }
  return prof;
}
