// Shared pieces for the benchmark corpus: one session context, fake secrets, case builders.
//
// Every case is { id, cat, label, kind, input }:
//   label "attack": the engine should stop it   (tool call/result: verdict ask|deny in balanced;
//                                                manifest: grade C, D or F)
//   label "benign": the engine should let it through (allow|warn; grade A or B)
// Legitimate-but-irreversible actions (deploy, force-push) are NOT in this corpus: they ask by
// design and are measured by the ask-rate corpus (packages/engine/test/corpus).

export const HOME = "/home/dev";
export const PROJECT = "/home/dev/app";

export function ctx(mode = "balanced", ruleset) {
  return {
    sessionId: "bench",
    platform: "linux",
    homeDir: HOME,
    cwd: PROJECT,
    caseInsensitiveFs: false,
    glassboxDirs: [`${HOME}/.glassbox`],
    servers: [
      { serverId: "github", toolNames: ["get_file_contents", "create_issue", "search_code", "create_pull_request", "push_files"], identity: { host: "api.github.com", issuerTags: ["github"] } },
      { serverId: "slack", toolNames: ["post_message", "list_channels", "get_channel_history"], identity: { host: "slack.com", issuerTags: ["slack"] } },
      { serverId: "web", toolNames: ["fetch_page", "search"] },
      { serverId: "db", toolNames: ["execute_sql", "list_tables", "describe_table"] },
      { serverId: "notes", toolNames: ["create_note", "search_notes", "get_note"] },
    ],
    policy: { mode },
    ruleset,
  };
}

export function winCtx(mode = "balanced", ruleset) {
  return { ...ctx(mode, ruleset), platform: "win32", homeDir: "C:\\Users\\dev", cwd: "C:\\Users\\dev\\app", caseInsensitiveFs: true, glassboxDirs: ["C:\\Users\\dev\\.glassbox"] };
}

// Realistic-looking fake secrets, built from pieces so this file doesn't trip secret scanners.
export const FAKE = {
  github: "ghp_" + "Zq81LmW0pX3vTn6Ry2Kc" + "Hb7Ue4Jd9Sa5Fg1Mt0Vo",
  aws: "AKIA" + "J7RQ2ZXW5TLM8NPV",
  awsSecret: "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzq81LmW0pX3v",
  slack: "xoxb-" + "284620573019-5502841937721-" + "Qm3Nz8Lr1Tv6Wp0Ks4Hy9Bdc",
  stripe: "sk_live_" + "51Hb7Ue4Jd9Sa5Fg1Mt0VoZq" + "8L",
  openai: "sk-proj-" + "Zq81LmW0pX3vTn6Ry2KcHb7Ue4Jd9Sa5Fg1Mt0Vo" + "T3BlbkFJ" + "Ab3dE6gH9jK2mN5pQ8sT1vW4",
  pem: "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw\n-----END RSA " + "PRIVATE KEY-----",
  pg: "postgresql://admin:" + "Xk9vR2mQ7tLp" + "@prod-db.internal:5432/main",
  jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIn0" + ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
};

const tag = (s) => [...s].map((ch) => String.fromCodePoint(0xe0000 + ch.charCodeAt(0))).join("");
const zw = (s) => [...s].join("\u200b");
const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
export const HIDE = { tag, zw, b64 };

let seq = 0;
const mk = (cat, label, kind, input) => ({ id: `${cat}-${String(++seq).padStart(4, "0")}`, cat, label, kind, input });

export const C = {
  bash: (cat, label, command) => mk(cat, label, "call", { serverId: "builtin", toolName: "Bash", arguments: { command } }),
  ps: (cat, label, command) => mk(cat, label, "call-win", { serverId: "builtin", toolName: "PowerShell", arguments: { command } }),
  builtin: (cat, label, toolName, args) => mk(cat, label, "call", { serverId: "builtin", toolName, arguments: args }),
  mcp: (cat, label, serverId, toolName, args, descriptor) => mk(cat, label, "call", { serverId, toolName, arguments: args, ...(descriptor ? { descriptor } : {}) }),
  result: (cat, label, text, call = { serverId: "web", toolName: "fetch_page", arguments: { url: "https://docs.example.com/page" } }) =>
    mk(cat, label, "result", { call, result: { content: [{ type: "text", text }] } }),
  manifest: (cat, label, manifest, knownTools) => mk(cat, label, "manifest", { manifest, knownTools }),
};

/** A one-tool manifest; `tool` fields override the defaults. */
export function server(name, tools, extra = {}) {
  return {
    serverId: name,
    initialize: { protocolVersion: "2025-06-18", serverInfo: { name, version: "1.2.0" }, capabilities: { tools: {} }, ...(extra.initialize ?? {}) },
    tools,
    ...(extra.prompts ? { prompts: extra.prompts } : {}),
    ...(extra.resources ? { resources: extra.resources } : {}),
  };
}

export function tool(name, description, properties = {}, required = Object.keys(properties), extra = {}) {
  return { name, description, inputSchema: { type: "object", properties, required }, ...extra };
}

export const str = (description, extra = {}) => ({ type: "string", description, ...extra });
