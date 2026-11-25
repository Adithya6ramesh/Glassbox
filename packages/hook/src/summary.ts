// Metadata-only summaries (the default): enough to say what happened, never the content.
// - shell: command name, a known subcommand, and flag names; never argument values
// - file tools: project-relative path, or ~/…/<file name> outside the project
// - search tools: pattern length only
// - WebFetch: host only
// - MCP tools: server and tool name
import path from "node:path";
import * as v from "valibot";
import { parseClaudeCodeToolName, redact } from "@glassbox-ai/engine";
import { SummaryFields, SummaryPath } from "@glassbox-ai/protocol";

export type Summary = v.InferOutput<typeof SummaryFields>;

/** Tools whose second word is a subcommand (`git push`, `npm test`), never a value. */
const SUBCOMMAND_TOOLS: ReadonlySet<string> = new Set([
  "git", "npm", "pnpm", "yarn", "bun", "deno", "docker", "podman", "kubectl", "helm", "gh", "cargo", "go", "dotnet",
  "pip", "pip3", "uv", "poetry", "terraform", "az", "gcloud", "aws", "systemctl", "brew", "apt", "apt-get", "winget",
  "choco", "scoop", "corepack", "vercel", "supabase", "wrangler", "flyctl", "heroku", "make", "just",
]);

const SPLIT = /[;&|`\n<>]|\$\(/;
const ENV_ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
const WIN_EXE = /^([A-Za-z]:\\[^"\r\n]*?\.(?:exe|cmd|bat|com|ps1))(?=\s|$)/i;
const NAME = /^[A-Za-z0-9._+-]{1,64}$/;
const MAX_CMD = 190;

function programName(token: string): string {
  if (/^['"$]/.test(token)) return "(command)";
  const base = token.split(/[\\/]/).pop() ?? "";
  const name = base.replace(/\.(exe|cmd|bat|com|ps1)$/i, "");
  return NAME.test(name) ? name : "(command)";
}

function flagName(token: string): string | null {
  if (token.startsWith("--")) {
    // Long flags: lower-case words only, value after "=" dropped.
    const m = /^--([a-z][a-z0-9-]{0,40})(?:=|$)/.exec(token);
    return m ? `--${m[1]}` : null;
  }
  if (!/^-[A-Za-z]/.test(token)) return null;
  if (/^-[A-Za-z]{1,3}$/.test(token)) return token; // -la, -rf, -m
  if (/^-[A-Z][a-z]+(?:[A-Z][a-z]+)*$/.test(token)) return token; // PowerShell: -Path, -Recurse
  return token.slice(0, 2); // glued value (-pS3cret) → -p
}

/** `git push --force origin main` → `git push --force`. Compound commands end in " …". */
export function summarizeCommand(command: string): string {
  const s = typeof command === "string" ? command.trim() : "";
  if (!s) return "";
  const compound = SPLIT.test(s);
  let head = (s.split(SPLIT)[0] ?? "").trim();

  let name: string;
  const exe = WIN_EXE.exec(head);
  if (exe) {
    name = programName(exe[1] ?? "");
    head = head.slice(exe[0].length);
  } else {
    const toks = head.split(/\s+/).filter(Boolean);
    while (toks[0] !== undefined && ENV_ASSIGN.test(toks[0])) toks.shift();
    const first = toks.shift();
    if (first === undefined) return compound ? "(command) …" : "";
    name = programName(first);
    head = toks.join(" ");
  }

  const rest = head.split(/\s+/).filter(Boolean);
  const parts = [name];
  const sub = rest[0];
  if (SUBCOMMAND_TOOLS.has(name.toLowerCase()) && sub !== undefined && /^[a-z][a-z0-9-]{0,31}$/.test(sub)) {
    parts.push(sub);
    rest.shift();
  }
  for (const t of rest) {
    const f = flagName(t);
    if (f === null || parts.includes(f)) continue;
    if (parts.join(" ").length + f.length + 1 > MAX_CMD) break;
    parts.push(f);
  }
  const out = parts.join(" ");
  return compound ? `${out} …` : out;
}

export interface PathContext {
  cwd: string;
  homeDir: string;
  caseInsensitive: boolean;
}

const isWinPath = (p: string) => /^[A-Za-z]:[\\/]/.test(p) || p.startsWith("\\\\");

/** Project-relative path, or `~/…/<file name>` for anything outside the project. */
export function summarizePath(file: string, pc: PathContext): string | undefined {
  if (typeof file !== "string" || !file) return undefined;
  const p = isWinPath(pc.cwd) || isWinPath(file) ? path.win32 : path.posix;
  const abs = p.resolve(pc.cwd, file);
  const rel = p.relative(p.resolve(pc.cwd), abs);
  let out: string;
  if (rel && !rel.startsWith("..") && !p.isAbsolute(rel)) out = rel.split(p.sep).join("/");
  else out = `~/…/${p.basename(abs)}`;
  try {
    const r = redact(out);
    if (typeof r.value === "string") out = r.value;
  } catch {
    return undefined;
  }
  return v.is(SummaryPath, out) ? out : undefined;
}

function hostOf(url: unknown): string | undefined {
  if (typeof url !== "string") return undefined;
  try {
    const host = new URL(url).host;
    return /^[A-Za-z0-9.-]+(:\d{1,5})?$/.test(host) ? host : undefined;
  } catch {
    return undefined;
  }
}

const FILE_KEY: Readonly<Record<string, string>> = { Read: "file_path", Write: "file_path", Edit: "file_path", NotebookEdit: "notebook_path" };
const COMMAND_TOOLS: ReadonlySet<string> = new Set(["Bash", "PowerShell", "Monitor"]);

/** Summary fields for a tool call. Every field is checked against the protocol schema; a field that fails is left out. */
export function summarize(toolName: string, input: Record<string, unknown>, pc: PathContext): Summary {
  const out: Record<string, unknown> = {};
  if (toolName.startsWith("mcp__")) {
    const t = parseClaudeCodeToolName(toolName);
    out["server"] = t.serverId;
    out["toolName"] = t.toolName;
  } else if (COMMAND_TOOLS.has(toolName)) {
    const cmd = typeof input["command"] === "string" ? summarizeCommand(input["command"]) : "";
    if (cmd) out["cmd"] = cmd;
  } else if (Object.hasOwn(FILE_KEY, toolName)) {
    const p = summarizePath(input[FILE_KEY[toolName] ?? ""] as string, pc);
    if (p) out["path"] = p;
  } else if (toolName === "Glob" || toolName === "Grep") {
    if (typeof input["pattern"] === "string") out["patternLength"] = input["pattern"].length;
  } else if (toolName === "WebFetch") {
    const h = hostOf(input["url"]);
    if (h) out["host"] = h;
  } else {
    out["toolName"] = toolName;
  }
  const clean: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(out)) {
    if (v.is(SummaryFields, { [k]: val })) clean[k] = val;
  }
  return clean as Summary;
}
