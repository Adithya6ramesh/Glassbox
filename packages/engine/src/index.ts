// @glassbox-ai/engine public API. Every function is synchronous, pure and
// total: none of them throws, and a failure never becomes a silent allow.
import { classifyBuiltin, classifyMcp } from "./action/tools.js";
import { pathCtxFrom } from "./action/paths.js";
import { DEFAULT_LIMITS } from "./limits.js";
import { analyzeServerImpl } from "./analysis/manifest.js";
import { checkServerRequestImpl, checkToolCallImpl, checkToolResultImpl, errorDecision, HIGH_RISK_UNKNOWN, intake } from "./analysis/gate.js";
import { renderForModel as render } from "./evidence/evidence.js";
import { fingerprintOf } from "./fingerprint/fingerprint.js";
import { diffImpl } from "./fingerprint/diff.js";
import { EMBEDDED_BASELINE as BASELINE } from "./ruleset/baseline.js";
import { redact as redactImpl } from "./secrets/redact.js";
import { scoreFindings } from "./grade/score.js";
import type {
  ActionContext, ActionRisk, AnalyzeOptions, Decision, DiffOptions, Finding, Fingerprint, FingerprintResult, LoadedRuleset,
  ManifestDiff, RedactOptions, Redacted, ServerReport, SessionContext, ToolDef,
} from "./types.js";
import { get, getString, isRecord } from "./util/misc.js";
import { ENGINE_VERSION as VERSION } from "./version.js";
import { resolveLimits } from "./limits.js";

export * from "./types.js";

/** Built-in Claude Code tools the engine knows, by category. Any other built-in tool is unanalyzable. */
export { BUILTIN_TOOLS } from "./action/builtin-tools.js";

export const ENGINE_VERSION: string = VERSION;
export const EMBEDDED_BASELINE: LoadedRuleset = BASELINE;

/** The only wording a grade may be presented with. */
export const GRADE_SCOPE_STATEMENT = "A grade checks what a server says about its tools. It doesn't inspect the server's code.";

const t = (): number => performance.now();

export function analyzeServer(manifest: unknown, opts?: AnalyzeOptions): ServerReport {
  const t0 = t();
  try {
    return analyzeServerImpl(manifest, isRecord(opts) ? opts : undefined, t0);
  } catch {
    const s = scoreFindings([], { partial: true });
    const fp = fingerprintOf(null, DEFAULT_LIMITS);
    return {
      grade: "F", score: 0, partial: true, caps: [{ cap: "F", reason: "Capped at F: the metadata couldn't be analyzed.", findingIds: [] }], deductions: s.deductions,
      findings: [], capabilityProfile: [], scope: "metadata-only", fingerprint: fp, rulesetVersion: "unknown", engineVersion: VERSION,
      degraded: true, degradedReasons: ["internal-error"], elapsedMs: Math.max(0, t() - t0),
    };
  }
}

export function fingerprint(manifest: unknown): FingerprintResult {
  try {
    const ink = intake(manifest, DEFAULT_LIMITS);
    if (ink.tooBig || !isRecord(ink.value)) return { ok: false, findings: [], degraded: true };
    return { ok: true, fingerprint: fingerprintOf(ink.value, DEFAULT_LIMITS), findings: [] };
  } catch {
    return { ok: false, findings: [], degraded: true };
  }
}

export function diffFingerprints(prev: Fingerprint, next: Fingerprint, opts?: DiffOptions): ManifestDiff {
  try {
    return diffImpl(prev, next, isRecord(opts) ? opts : undefined);
  } catch {
    return { changed: true, changes: [{ kind: "fingerprint-incomparable", item: "", pointer: "", detail: "the fingerprints can't be compared" }], findings: [], degraded: true };
  }
}

export function checkToolCall(input: unknown, ctx: SessionContext): Decision {
  const t0 = t();
  try {
    return checkToolCallImpl(input, ctx, t0);
  } catch {
    return errorDecision(t0, modeOf(ctx));
  }
}

export function checkToolResult(input: unknown, ctx: SessionContext): Decision {
  const t0 = t();
  try {
    return checkToolResultImpl(input, ctx, t0);
  } catch {
    return errorDecision(t0, modeOf(ctx), { ...HIGH_RISK_UNKNOWN, level: "read" });
  }
}

export function checkServerRequest(input: unknown, ctx: SessionContext): Decision {
  const t0 = t();
  try {
    return checkServerRequestImpl(input, ctx, t0);
  } catch {
    return errorDecision(t0, modeOf(ctx));
  }
}

function modeOf(ctx: unknown): SessionContext["policy"]["mode"] | undefined {
  try {
    const m = getString(get(ctx, "policy"), "mode");
    return m === "strict" || m === "balanced" || m === "autopilot" ? m : undefined;
  } catch {
    return undefined;
  }
}

export function classifyAction(input: unknown, ctx?: ActionContext): ActionRisk {
  try {
    const limits = resolveLimits(undefined);
    const ink = intake(input, limits);
    const v = ink.value;
    const serverId = getString(v, "serverId");
    const toolName = getString(v, "toolName");
    if (serverId === undefined || toolName === undefined) return HIGH_RISK_UNKNOWN;
    const c = (isRecord(ctx) ? ctx : {}) as ActionContext;
    const pctx = pathCtxFrom({
      platform: c.platform === "win32" || c.platform === "darwin" ? c.platform : "linux",
      homeDir: typeof c.homeDir === "string" ? c.homeDir : "/home/unknown",
      cwd: typeof c.cwd === "string" ? c.cwd : null,
      caseInsensitiveFs: c.caseInsensitiveFs === true,
      glassboxDirs: Array.isArray(c.glassboxDirs) ? c.glassboxDirs : [],
    });
    const tc = { pctx, maxCommandBytes: limits.maxCommandBytes, maxSqlBytes: limits.maxSqlBytes };
    const args = get(v, "arguments") ?? Object.create(null);
    const acc = serverId === "builtin" ? classifyBuiltin(toolName, args, tc) : classifyMcp(toolName, args, isRecord(get(v, "descriptor")) ? (get(v, "descriptor") as ToolDef) : undefined, tc).acc;
    return { level: acc.level, tags: [...acc.tags].sort(), unanalyzable: acc.unanalyzableFlag, selfProtection: acc.selfProtection, reasons: [...acc.reasons, ...acc.unanalyzableReasons].slice(0, 20) };
  } catch {
    return HIGH_RISK_UNKNOWN;
  }
}

export function redact(value: unknown, opts?: RedactOptions): Redacted {
  return redactImpl(value, isRecord(opts) ? opts : undefined);
}

export function renderForModel(findings: readonly Finding[]): string {
  return render(findings);
}

/** Splits Claude Code tool names: mcp__<server>__<tool> and mcp__plugin_<plugin>_<server>__<tool>. */
export function parseClaudeCodeToolName(name: string): { serverId: string; toolName: string; plugin?: string } {
  try {
    if (typeof name !== "string" || !name.startsWith("mcp__")) return { serverId: "builtin", toolName: typeof name === "string" ? name : "" };
    const rest = name.slice(5);
    const sep = rest.indexOf("__");
    if (sep < 0) return { serverId: "builtin", toolName: name };
    const server = rest.slice(0, sep);
    const tool = rest.slice(sep + 2);
    if (server.startsWith("plugin_")) {
      const p = server.slice(7);
      const u = p.indexOf("_");
      if (u > 0) return { serverId: p.slice(u + 1), toolName: tool, plugin: p.slice(0, u) };
    }
    return { serverId: server, toolName: tool };
  } catch {
    return { serverId: "builtin", toolName: "" };
  }
}
