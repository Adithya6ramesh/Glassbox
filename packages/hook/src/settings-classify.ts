// Classifying a change to a Claude Code settings file. Pure: no file access.
//
// Owner decisions (2026-11-27):
// - cosmetic keys (an allow-list) and known ordinary keys → warn and record;
// - dangerous changes → strict mode until the user confirms in a terminal;
// - unknown keys are dangerous until classified, at any depth;
// - changes that would stop Glassbox running (disableAllHooks, the Glassbox plugin turned off,
//   a hook running Glassbox removed or changed) are also blocked when ConfigChange reports them.
// Key lists follow the Claude Code settings reference (checked 2026-11-27).
// The result carries key names only, never values.
import { isPlainRecord } from "@glassbox-ai/protocol";

export type SettingsLevel = "unchanged" | "cosmetic" | "ordinary" | "dangerous";
export type SettingsReason =
  | "hooks" | "disable-all-hooks" | "glassbox-plugin" | "glassbox-hook" | "plugin" | "default-mode" | "env"
  | "helper-command" | "mcp" | "broad-allow" | "sandbox" | "network-auth" | "unknown-key" | "unreadable";

export interface SettingsClassification {
  level: SettingsLevel;
  /** The change would stop Glassbox running: ConfigChange blocks it. */
  block: boolean;
  changedKeys: string[];
  reasons: SettingsReason[];
}

/** Settings files are strict JSON (comments and trailing commas are syntax errors). */
export const MAX_SETTINGS_BYTES = 1024 * 1024;
const MAX_KEYS = 50;
const MAX_DEPTH = 64;

export function parseSettingsBytes(buf: Buffer): { ok: true; value: Record<string, unknown> } | { ok: false } {
  if (buf.length > MAX_SETTINGS_BYTES) return { ok: false };
  let text = buf.toString("utf8");
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  try {
    const v: unknown = JSON.parse(text);
    return isPlainRecord(v) ? { ok: true, value: v } : { ok: false };
  } catch {
    return { ok: false };
  }
}

const COSMETIC = new Set([
  "theme", "editorMode", "tui", "verbose", "viewMode", "spinnerVerbs", "spinnerTipsEnabled", "spinnerTipsOverride",
  "syntaxHighlightingDisabled", "timeFormat", "timeZone", "wheelScrollAccelerationEnabled", "axScreenReader", "language",
  "outputStyle", "preferredNotifChannel",
]);

/** Known keys whose change is recorded and warned about, but isn't dangerous. */
const ORDINARY = new Set([
  "$schema", "model", "availableModels", "fallbackModel", "modelSettings", "effortLevel", "switchModelsOnFlag", "ultracode",
  "alwaysThinkingEnabled", "attribution", "includeCoAuthoredBy", "includeGitInstructions", "prUrlTemplate",
  "autoUpdatesChannel", "minimumVersion", "cleanupPeriodDays", "desktopSessionCleanupPeriodDays", "autoCompactEnabled",
  "autoCompactWindow", "autoMemoryEnabled", "bashOutputMaxChars", "claudeMdExcludes", "fileCheckpointingEnabled",
  "idleCompaction", "skillListingBudgetFraction", "skillListingMaxDescChars", "skillOverrides", "disableBundledSkills",
  "teammateMode", "disableAgentView", "isolatePeerMachines", "disableWorkflows", "enableWorkflows",
  "workflowKeywordTriggerEnabled", "workflowSizeGuideline", "askUserQuestionTimeout", "autoContinueAtUsageLimit",
  "enableArtifact", "disableArtifact", "disableDeepLinkRegistration", "footerLinksRegexes", "feedbackDrafts",
  "feedbackSurveyRate", "skipAutoPermissionPrompt", "disableClaudeAiConnectors", "syncClaudeAiPlugins",
  "syncClaudeAiSkills", "disableSkillShellExecution", "disableAutoMode", "disableRemoteControl", "disabledMcpjsonServers",
  "deniedMcpServers",
]);

const HELPER_COMMANDS = new Set([
  "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper", "policyHelper",
  "processWrapper", "sshHostCommands", "fileSuggestion",
]);
const NETWORK_AUTH = new Set([
  "forceLoginMethod", "forceLoginOrgUUID", "forceLoginGatewayUrl", "allowedHttpHookUrls", "httpHookAllowedEnvVars",
  "skipWebFetchPreflight", "sshConfigs",
]);
const PLUGIN_KEYS = new Set(["extraKnownMarketplaces", "additionalMarketplaces", "pluginConfigs", "prependPlugins", "appendPlugins"]);
const MCP_KEYS = new Set(["allowedMcpServers", "mcpServers", "managedMcpServers"]);

/** permissions.* keys: tightening or neutral ones are ordinary; the rest are handled below. */
const PERMISSIONS_ORDINARY = new Set([
  "deny", "ask", "additionalDirectories", "disableBypassPermissionsMode", "disableAutoMode",
  "blockReadsOutsideWorkingDirectories", "blockWritesOutsideWorkingDirectories", "denyInsteadOfPrompting",
]);
const PERMISSIVE_MODES = new Set(["bypassPermissions", "acceptEdits", "auto"]);
const STATUSLINE_COSMETIC = new Set(["padding", "hideVimModeIndicator"]);

/** Env vars that run code, change which programs run, or redirect config, traffic or trust. Upper-cased. */
const DANGEROUS_ENV = new Set([
  "BASH_ENV", "ENV", "PATH", "PATHEXT", "PROMPT_COMMAND", "ZDOTDIR", "SHELL", "HOME", "USERPROFILE", "APPDATA",
  "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "COMSPEC", "PSMODULEPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
  "JDK_JAVA_OPTIONS", "DOTNET_STARTUP_HOOKS", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE",
  "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "BETA_TRACING_ENDPOINT", "EDITOR", "VISUAL", "PAGER",
  "LESSOPEN", "LESSCLOSE", "BROWSER", "TMPDIR", "TEMP", "TMP",
]);
const DANGEROUS_ENV_PREFIXES = [
  "LD_", "DYLD_", "NODE_", "NPM_CONFIG_", "PYTHON", "PERL", "RUBY", "GIT_", "CLAUDE_", "ANTHROPIC_", "OTEL_", "BUN_",
  "DENO_", "MSYS", "GCONV_",
];
const isDangerousEnv = (name: string) => {
  const n = name.toUpperCase();
  return DANGEROUS_ENV.has(n) || DANGEROUS_ENV_PREFIXES.some((p) => n.startsWith(p));
};

/** Plugin ids are `name@marketplace`. */
const isGlassboxPlugin = (id: string) => /^glassbox(-ai)?@/i.test(id);

/** An allow rule with no specifier, or one that is only wildcards, matches everything the tool does. */
function isBroadRule(rule: unknown): boolean {
  if (typeof rule !== "string") return true;
  const m = /^([^()]*)(?:\((.*)\))?$/s.exec(rule.trim());
  if (!m) return true;
  const tool = (m[1] ?? "").trim();
  const spec = m[2];
  if (tool === "" || tool.includes("*")) return true;
  if (/^mcp__[^_]+(?:__\*?)?$/i.test(tool)) return true; // a whole MCP server
  return spec === undefined || /^[\s*:]*$/.test(spec);
}

// ---------------------------------------------------------------------------------------------

const own = (o: Record<string, unknown>, k: string) => (Object.hasOwn(o, k) ? o[k] : undefined);
const rec = (x: unknown): Record<string, unknown> => (isPlainRecord(x) ? x : {});

function canon(x: unknown, depth = 0): string {
  if (depth > MAX_DEPTH) return "\u0000deep";
  if (x === null || typeof x !== "object") return JSON.stringify(x) ?? "undefined";
  if (Array.isArray(x)) return `[${x.map((e) => canon(e, depth + 1)).join(",")}]`;
  const o = x as Record<string, unknown>;
  return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canon(o[k], depth + 1)}`).join(",")}}`;
}
const same = (a: unknown, b: unknown) => canon(a) === canon(b);
const truthy = (x: unknown) => x !== undefined && x !== null && x !== false && x !== 0 && x !== "";

/** Changed keys of two objects (own keys only, so "__proto__" from JSON is just a key). */
function changed(a: Record<string, unknown>, b: Record<string, unknown>): string[] {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].filter((k) => !same(own(a, k), own(b, k))).sort();
}

const asArray = (x: unknown): unknown[] => (Array.isArray(x) ? x : []);
const added = (a: unknown, b: unknown) => {
  const before = new Set(asArray(a).map((e) => canon(e)));
  return asArray(b).filter((e) => !before.has(canon(e)));
};

/** A key name made safe to report: printable, plain characters, capped. */
function safeKey(k: string): string {
  const s = k.replace(/[^A-Za-z0-9_$@.*:/()-]/g, "_").slice(0, 128);
  return s.length > 0 ? s : "_";
}

/** Commands of the hooks in a `hooks` value that mention Glassbox (canonical form, to compare). */
function glassboxHooks(hooks: unknown): Set<string> {
  const out = new Set<string>();
  for (const [event, groups] of Object.entries(rec(hooks))) {
    for (const g of asArray(groups)) {
      for (const h of asArray(rec(g)["hooks"])) {
        const cmd = rec(h)["command"];
        if (typeof cmd === "string" && /glassbox/i.test(cmd)) out.add(`${event}\u0000${canon(rec(g)["matcher"])}\u0000${canon(h)}`);
      }
    }
  }
  return out;
}

const RANK: Record<SettingsLevel, number> = { unchanged: 0, cosmetic: 1, ordinary: 2, dangerous: 3 };

export function classifySettingsChange(before: unknown, after: unknown): SettingsClassification {
  if (after === null || (after !== undefined && !isPlainRecord(after))) {
    return { level: "dangerous", block: false, changedKeys: [], reasons: ["unreadable"] };
  }
  const a = rec(before);
  const b = rec(after);
  let level: SettingsLevel = "unchanged";
  let block = false;
  const keys: string[] = [];
  const reasons = new Set<SettingsReason>();
  const raise = (l: SettingsLevel) => { if (RANK[l] > RANK[level]) level = l; };
  const danger = (r: SettingsReason) => { raise("dangerous"); reasons.add(r); };
  const key = (k: string) => { if (keys.length < MAX_KEYS) keys.push(safeKey(k)); };

  for (const k of changed(a, b)) {
    const va = own(a, k);
    const vb = own(b, k);
    if (COSMETIC.has(k)) { key(k); raise("cosmetic"); continue; }
    if (ORDINARY.has(k)) { key(k); raise("ordinary"); continue; }

    switch (k) {
      case "hooks": {
        for (const ev of changed(rec(va), rec(vb))) key(`hooks.${ev}`);
        danger("hooks");
        const gbBefore = glassboxHooks(va);
        const gbAfter = glassboxHooks(vb);
        if ([...gbBefore].some((h) => !gbAfter.has(h))) { block = true; reasons.add("glassbox-hook"); }
        break;
      }
      case "disableAllHooks":
        key(k);
        if (truthy(vb)) { danger("disable-all-hooks"); block = true; } else raise("ordinary");
        break;
      case "enabledPlugins": {
        const pa = rec(va);
        const pb = rec(vb);
        // Whether Claude Code matches plugin ids without regard to case isn't documented: assume
        // it may, so any spelling of an enabled Glassbox id turned off (or gone) counts.
        const lower = (o: Record<string, unknown>) => Object.keys(o).filter(isGlassboxPlugin).map((id) => [id.toLowerCase(), o[id]] as const);
        const onBefore = new Set(lower(pa).filter(([, v]) => v === true).map(([id]) => id));
        const after = lower(pb);
        if ([...onBefore].some((id) => after.some(([i, v]) => i === id && v !== true) || !after.some(([i, v]) => i === id && v === true))) {
          danger("glassbox-plugin");
          block = true;
        }
        for (const id of changed(pa, pb)) {
          key(`enabledPlugins.${id}`);
          if (isGlassboxPlugin(id)) {
            raise("ordinary");
          } else if (own(pb, id) === true) {
            danger("plugin"); // a newly enabled plugin can bring hooks and MCP servers
          } else {
            raise("ordinary");
          }
        }
        break;
      }
      case "permissions": {
        const pa = rec(va);
        const pb = rec(vb);
        for (const sub of changed(pa, pb)) {
          key(`permissions.${sub}`);
          if (PERMISSIONS_ORDINARY.has(sub)) { raise("ordinary"); continue; }
          if (sub === "allow") {
            if (added(own(pa, sub), own(pb, sub)).some(isBroadRule)) danger("broad-allow"); else raise("ordinary");
          } else if (sub === "defaultMode") {
            const m = own(pb, sub);
            if (m !== undefined && (typeof m !== "string" || PERMISSIVE_MODES.has(m) || !["default", "manual", "plan", "dontAsk"].includes(m))) danger("default-mode");
            else raise("ordinary");
          } else {
            danger("unknown-key");
          }
        }
        break;
      }
      case "skipDangerousModePermissionPrompt":
      case "useAutoModeDuringPlan":
      case "autoMode":
        key(k);
        if (k === "useAutoModeDuringPlan" && vb === false) raise("ordinary"); else danger("default-mode");
        break;
      case "statusLine": {
        const sa = rec(va);
        const sb = rec(vb);
        const subs = changed(sa, sb);
        key(k);
        if (isPlainRecord(va) && isPlainRecord(vb) && subs.every((s) => STATUSLINE_COSMETIC.has(s))) raise("cosmetic");
        else danger("helper-command");
        break;
      }
      case "env": {
        const ea = rec(va);
        const eb = rec(vb);
        if (!isPlainRecord(vb) && vb !== undefined) { key(k); danger("unknown-key"); break; }
        for (const name of changed(ea, eb)) {
          key(`env.${name}`);
          if (isDangerousEnv(name)) danger("env"); else raise("ordinary");
        }
        break;
      }
      case "enableAllProjectMcpServers":
      case "allowAllClaudeAiMcps":
        key(k);
        if (truthy(vb)) danger("mcp"); else raise("ordinary");
        break;
      case "enabledMcpjsonServers":
        key(k);
        if (added(va, vb).length > 0) danger("mcp"); else raise("ordinary");
        break;
      case "sandbox":
        for (const sub of changed(rec(va), rec(vb))) key(`sandbox.${sub}`);
        if (!isPlainRecord(va) && !isPlainRecord(vb)) key(k);
        danger("sandbox");
        break;
      default:
        key(k);
        if (HELPER_COMMANDS.has(k)) danger("helper-command");
        else if (MCP_KEYS.has(k)) danger("mcp");
        else if (PLUGIN_KEYS.has(k)) danger("plugin");
        else if (NETWORK_AUTH.has(k)) danger("network-auth");
        else danger("unknown-key");
    }
  }
  if (level === "unchanged" && !same(a, b)) raise("ordinary");
  return { level, block, changedKeys: keys, reasons: [...reasons] };
}
