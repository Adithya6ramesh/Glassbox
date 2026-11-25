// Other coding-agent CLIs (spec §7.10, rev 11, engine 0.1.2). Treated like `claude`:
// - starting one is a nested agent (exec.nested-agent: a liftable ask);
// - a flag, environment variable or option that turns off its approvals or its sandbox, or
//   points it at another configuration, is denied (CP-SELF-003), like
//   `claude --dangerously-skip-permissions`.
// Only flags confirmed in each tool's official docs or source (checked 2026-11-25) are listed.
// Unconfirmed spellings are left out on purpose; launching the tool still asks.
import type { Acc } from "./acc.js";
import { normalizeFull, type NormPath, type PathCtx } from "./paths.js";

/** A flag that takes a value: denied only for the listed values (or any value when `values` is "any"). */
interface ValueFlag {
  flags: readonly string[];
  values: readonly string[] | "any";
  /** Only for these keys of a `key=value` setting (Codex `-c approval_policy=…`). */
  keys?: readonly string[];
}

export interface AgentCli {
  tool: string;
  exes: readonly string[];
  /** Boolean flags that turn off approvals or the sandbox. */
  deny: readonly string[];
  denyValues: readonly ValueFlag[];
  /** Environment variables that are denied whatever their value. */
  denyEnv: readonly string[];
  /** Environment variables denied only for these values. */
  denyEnvValues: Readonly<Record<string, readonly string[]>>;
}

const cli = (c: Partial<AgentCli> & Pick<AgentCli, "tool" | "exes">): AgentCli => ({ deny: [], denyValues: [], denyEnv: [], denyEnvValues: {}, ...c });

export const AGENT_CLIS: readonly AgentCli[] = [
  cli({
    tool: "OpenAI Codex", exes: ["codex"],
    deny: ["--dangerously-bypass-approvals-and-sandbox", "--yolo", "--approve-for-me", "--not-so-yolo", "--dangerously-bypass-hook-trust", "--ignore-rules"],
    denyValues: [
      { flags: ["-a", "--ask-for-approval"], values: ["never"] },
      { flags: ["-s", "--sandbox"], values: ["danger-full-access"] },
      { flags: ["-c", "--config"], values: "any", keys: ["approval_policy", "sandbox_mode", "default_permissions"] },
    ],
    denyEnv: ["CODEX_HOME"],
  }),
  cli({
    tool: "Gemini CLI", exes: ["gemini"],
    deny: ["--yolo", "-y", "--skip-trust"],
    denyValues: [{ flags: ["--approval-mode"], values: ["yolo"] }],
    denyEnv: ["GEMINI_CLI_HOME", "SEATBELT_PROFILE"],
  }),
  cli({ tool: "Aider", exes: ["aider"], deny: ["--yes-always", "--yes"], denyEnv: ["AIDER_YES_ALWAYS", "AIDER_YES"] }),
  cli({
    tool: "Cursor CLI", exes: ["agent", "cursor-agent"],
    deny: ["-f", "--force", "--yolo", "--approve-mcps", "--trust"],
    denyValues: [{ flags: ["--sandbox"], values: ["disabled"] }],
    denyEnv: ["CURSOR_CONFIG_DIR"],
  }),
  cli({
    tool: "opencode", exes: ["opencode"],
    deny: ["--auto", "--yolo", "--dangerously-skip-permissions"],
    denyEnv: ["OPENCODE_PERMISSION", "OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG_CONTENT"],
  }),
  cli({ tool: "Goose", exes: ["goose"], deny: ["--dangerously-unauthenticated"], denyEnv: ["GOOSE_PATH_ROOT"], denyEnvValues: { GOOSE_MODE: ["auto"] } }),
  cli({ tool: "Amp", exes: ["amp"], deny: ["--dangerously-allow-all"] }),
  cli({ tool: "Crush", exes: ["crush"], deny: ["--yolo"] }),
  cli({ tool: "GitHub Copilot CLI", exes: ["copilot"], deny: ["--allow-all-tools", "--allow-all", "--yolo", "--allow-all-paths", "--allow-all-urls"], denyEnv: ["COPILOT_HOME"] }),
  cli({ tool: "Kiro CLI", exes: ["kiro-cli", "kiro"], deny: ["--trust-all-tools"], denyEnv: ["KIRO_HOME"] }),
  cli({ tool: "Cline CLI", exes: ["cline"], deny: ["-y", "--yolo"] }),
  cli({ tool: "Qwen Code", exes: ["qwen"] }), // no flag confirmed in official docs: launching asks
];

const BY_EXE: ReadonlyMap<string, AgentCli> = new Map(AGENT_CLIS.flatMap((c) => c.exes.map((e) => [e, c] as const)));

/** The agent CLI a command name starts, if any (case-insensitive, `.exe`/`.cmd` dropped). */
export function agentCliFor(commandName: string): AgentCli | undefined {
  const n = commandName.toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, "");
  return BY_EXE.get(n.split(/[\\/]/).pop() ?? n);
}

/**
 * npm packages whose `bin` is an agent CLI (checked against the npm registry 2026-11-25), so a
 * package runner (`npx @openai/codex --yolo`) is analyzed like the CLI itself.
 */
export const AGENT_PACKAGES: Readonly<Record<string, string>> = {
  "@anthropic-ai/claude-code": "claude",
  "@openai/codex": "codex",
  "@google/gemini-cli": "gemini",
  "opencode-ai": "opencode",
  "@qwen-code/qwen-code": "qwen",
  "@github/copilot": "copilot",
  "@sourcegraph/amp": "amp",
  "@charmland/crush": "crush",
  cline: "cline",
};

/** The CLI a package spec (`@openai/codex@1.2.3`, `opencode-ai@latest`) provides, if it is an agent. */
export function agentPackageBin(spec: string): string | undefined {
  const s = spec.toLowerCase();
  const at = s.indexOf("@", s.startsWith("@") ? 1 : 0);
  const name = at > 0 ? s.slice(0, at) : s;
  return Object.hasOwn(AGENT_PACKAGES, name) ? AGENT_PACKAGES[name] : undefined;
}

const matches = (v: string, flag: string) => v === flag || v.startsWith(flag + "=");

/**
 * Analyze one agent CLI call. `vals` are the argument values (null = not known statically);
 * `env` maps environment variables set for this command to their value (null = not literal).
 */
export function agentCliCommand(a: AgentCli, vals: readonly (string | null)[], env: ReadonlyMap<string, string | null>, acc: Acc): void {
  const why = `starts ${a.tool} with approvals or its sandbox turned off`;
  for (const [name, value] of env) {
    if (a.denyEnv.includes(name)) { acc.protect("CP-SELF-003", `starts ${a.tool} with a different configuration (${name})`); return; }
    const bad = a.denyEnvValues[name];
    if (bad && (value === null || bad.includes(value.toLowerCase()))) { acc.protect("CP-SELF-003", `${why} (${name})`); return; }
  }
  for (let i = 0; i < vals.length; i++) {
    const v = vals[i];
    if (v === null || v === undefined) continue;
    if (a.deny.some((f) => matches(v, f))) { acc.protect("CP-SELF-003", `${why} (${v.split("=")[0]})`); return; }
    for (const vf of a.denyValues) {
      for (const f of vf.flags) {
        let value: string | null | undefined;
        if (v === f) value = vals[i + 1];
        else if (v.startsWith(f + "=")) value = v.slice(f.length + 1);
        else if (f.length === 2 && v.startsWith(f) && v.length > 2) value = v.slice(2); // clap-style -anever
        else continue;
        if (value === null || value === undefined) { acc.unanalyzable(`${a.tool}: ${f} with a value that isn't known statically`); return; }
        const val = value.replace(/^["']|["']$/g, "").toLowerCase();
        const hit = vf.keys ? vf.keys.some((k) => val.startsWith(k + "=") || val.startsWith(k + ".") || val === k) : vf.values === "any" || vf.values.includes(val);
        if (hit) { acc.protect("CP-SELF-003", `${why} (${f} ${val.slice(0, 40)})`); return; }
      }
    }
  }
  // An argument that isn't known statically could be one of the flags above.
  if (vals.some((v) => v === null)) { acc.unanalyzable(`${a.tool} with arguments that aren't known statically`); return; }
  if (vals.length === 1 && ["--help", "-h", "--version", "-v", "-V"].includes(vals[0] ?? "")) return;
  acc.tag("high-risk", "exec.nested-agent");
  acc.reason(`starts a nested agent (${a.tool})`);
}

// ── Their configuration and instruction files (agent config) ────────────

const USER_DIRS = [".codex", ".gemini", ".cursor", ".config/opencode", ".config/goose", "appdata/roaming/block/goose", ".config/amp", ".qwen", ".config/crush", ".copilot", ".kiro"];
const USER_FILES = [".aider.conf.yml"];
const SYSTEM_DIRS = ["/etc/gemini-cli", "/library/application support/geminicli", "c:/programdata/gemini-cli", "c:/programdata/opencode", "c:/programdata/ampcode"];
const PROJECT_DIRS = [".codex", ".gemini", ".cursor", ".opencode", ".amp", ".qwen"];
const PROJECT_FILES = ["opencode.json", "opencode.jsonc", ".aider.conf.yml", ".goosehints", ".crushrc", "crushrc", "agents.md", "gemini.md", "qwen.md", "crush.md"];

/**
 * Is this normalized, lower-cased path another agent CLI's configuration or instruction file?
 * `home` and `project` are normalized and lower-cased too (project may be null).
 */
export function isAgentConfigPath(p: string, home: string, project: string | null): boolean {
  const under = (dir: string) => p === dir || p.startsWith(dir + "/");
  if (USER_DIRS.some((d) => under(`${home}/${d}`)) || USER_FILES.some((f) => p === `${home}/${f}`)) return true;
  if (SYSTEM_DIRS.some((d) => under(d))) return true;
  if (project !== null && under(project)) {
    const rel = p.slice(project.length + 1);
    const segs = rel.split("/");
    if (segs.some((s, i) => i < segs.length - 1 && PROJECT_DIRS.includes(s))) return true;
    if (PROJECT_FILES.includes(segs[segs.length - 1] ?? "")) return true;
  }
  return false;
}

/** A write (or move or delete) of another agent's config or instruction file: config.agent (a liftable ask). */
export function agentConfigWrite(np: NormPath | null, pctx: PathCtx, acc: Acc): void {
  if (np === null || np.path === null) return;
  const norm = (x: string | null) => (x === null ? null : normalizeFull(x, { ...pctx, cwd: null }));
  const lower = (x: string | null) => (x === null ? null : (x.endsWith("/") && x.length > 1 ? x.slice(0, -1) : x).toLowerCase());
  const home = lower(norm(pctx.homeDir));
  if (home === null) return;
  if (isAgentConfigPath(np.path.toLowerCase(), home, lower(norm(pctx.cwd)))) {
    acc.tag("high-risk", "config.agent");
    acc.reason("writes another agent's configuration or instructions");
  }
}
