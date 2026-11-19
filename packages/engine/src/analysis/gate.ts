// The gate: checkToolCall / checkToolResult / checkServerRequest (engine-spec §4, §6).
import { Acc } from "../action/acc.js";
import { pathCtxFrom } from "../action/paths.js";
import { classifyBuiltin, classifyMcp, type ToolCtx } from "../action/tools.js";
import { snapshot } from "../intake/snapshot.js";
import { parseJsonStrict, type IntakeIssue } from "../intake/json.js";
import { resolveLimits } from "../limits.js";
import { decide } from "../policy/decide.js";
import { detectSecrets } from "../secrets/detect.js";
import { redactValue } from "../secrets/redact.js";
import type {
  ActionRisk, ActionTag, Decision, Finding, Limits, LoadedRuleset, PolicyChoice, ServerRequestKind, SessionContext, SessionSignal, ToolDef, Verdict,
} from "../types.js";
import { sha256Hex } from "../util/hash.js";
import { jcs } from "../util/jcs.js";
import { get, getString, isRecord, utf8Length } from "../util/misc.js";
import { ENGINE_VERSION } from "../version.js";
import { initMs } from "../util/initclock.js";
import { genericFields, type Field } from "./fields.js";
import { dedupe, FindingFactory, sevRank, sortFindings } from "./findings.js";
import { tokenize } from "./match.js";
import { scanFields } from "./scan.js";

const now = (): number => performance.now();

export const HIGH_RISK_UNKNOWN: ActionRisk = Object.freeze({ level: "high-risk", tags: Object.freeze(["exec.unknown"]) as readonly ActionTag[], unanalyzable: false, selfProtection: false, reasons: Object.freeze(["the action couldn't be classified"]) as readonly string[] });

// ── Context validation ───────────────────────────────────────────────────

interface Ctx {
  raw: SessionContext;
  limits: Limits;
  ruleset: LoadedRuleset;
  mode: SessionContext["policy"]["mode"];
  evidenceMode: "snippet" | "none";
  signals: SessionSignal[];
  callIndex: number;
  protectionDegraded: boolean;
}

function validateCtx(c: unknown): Ctx | null {
  if (!isRecord(c)) return null;
  const policy = get(c, "policy");
  const mode = getString(policy, "mode");
  const ruleset = get(c, "ruleset");
  if (mode !== "strict" && mode !== "balanced" && mode !== "autopilot") return null;
  if (!isRecord(ruleset) || !Array.isArray(get(ruleset, "rules")) || !Array.isArray(get(ruleset, "irreversibleTags"))) return null;
  if (typeof get(c, "homeDir") !== "string" || typeof get(c, "cwd") !== "string" || !Array.isArray(get(c, "glassboxDirs"))) return null;
  const platform = get(c, "platform");
  if (platform !== "linux" && platform !== "darwin" && platform !== "win32") return null;
  const raw = c as unknown as SessionContext;
  const limits = resolveLimits(raw.limits);
  const all = Array.isArray(raw.signals) ? raw.signals.filter((s) => isRecord(s) && typeof get(s, "kind") === "string" && typeof get(s, "atCall") === "number") : [];
  const callIndex = all.reduce((m, s) => Math.max(m, s.atCall), 0) + 1;
  const signals = all.filter((s) => s.kind === "protection-degraded" || callIndex - s.atCall <= limits.signalTtlCalls);
  const rs = raw.ruleset;
  return {
    raw,
    limits,
    ruleset: rs,
    mode,
    evidenceMode: raw.evidenceMode === "none" ? "none" : "snippet",
    signals,
    callIndex,
    protectionDegraded: rs.protectionDegraded === true || signals.some((s) => s.kind === "protection-degraded"),
  };
}

function toolCtx(c: Ctx): ToolCtx {
  const r = c.raw;
  return {
    pctx: pathCtxFrom({ ...r, cwd: r.cwd }),
    maxCommandBytes: c.limits.maxCommandBytes,
    maxSqlBytes: c.limits.maxSqlBytes,
  };
}

// ── Intake ───────────────────────────────────────────────────────────────

interface Intake { value: unknown; issues: IntakeIssue[]; degraded: boolean; tooBig: boolean }

export function intake(input: unknown, limits: Limits): Intake {
  if (typeof input === "string" || input instanceof Uint8Array) {
    const size = typeof input === "string" ? utf8Length(input) : input.length;
    if (size > limits.maxInputBytes) return { value: undefined, issues: [{ code: "CP-LIMIT-001" }], degraded: true, tooBig: true };
    const r = parseJsonStrict(input, { maxDepth: limits.maxDepth, maxNodes: limits.maxNodes });
    return { value: r.value, issues: r.issues, degraded: r.degraded, tooBig: false };
  }
  const s = snapshot(input, { maxDepth: limits.maxDepth, maxNodes: limits.maxNodes, maxBytes: limits.maxInputBytes });
  return { value: s.value, issues: s.issues, degraded: s.degraded, tooBig: false };
}

function issueFindings(issues: IntakeIssue[], ff: FindingFactory): Finding[] {
  const out: (Finding | null)[] = [];
  const seen = new Set<string>();
  for (const i of issues) {
    const k = i.code + (i.pointer ?? "");
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(ff.make({ ruleId: i.code, location: i.pointer ?? "" }));
  }
  return out.filter((x): x is Finding => x !== null);
}

// ── Shared finishing ─────────────────────────────────────────────────────

function digest(v: unknown): string {
  try {
    return sha256Hex(jcs(v ?? null));
  } catch {
    return sha256Hex("");
  }
}

function rulesetVersion(r: LoadedRuleset): string {
  return `${r.rulesetId}@${r.version}+${r.sequence}`;
}

function suppress(findings: Finding[], c: Ctx, ff: FindingFactory): { kept: Finding[]; suppressed: { ruleId: string; count: number }[] } {
  const disabled = new Set(Array.isArray(c.raw.policy.disabledRules) ? c.raw.policy.disabledRules : []);
  const counts = new Map<string, number>();
  const kept = findings.filter((f) => {
    const r = ff.rule(f.ruleId);
    if (!disabled.has(f.ruleId) || !r || !r.suppressible) return true;
    counts.set(f.ruleId, (counts.get(f.ruleId) ?? 0) + 1);
    return false;
  });
  return { kept, suppressed: [...counts].map(([ruleId, count]) => ({ ruleId, count })) };
}

function integrityFindings(c: Ctx, ff: FindingFactory): Finding[] {
  const out: (Finding | null)[] = [];
  if (c.protectionDegraded) out.push(ff.make({ ruleId: c.ruleset.degradedCause === "downgrade" ? "CP-INTEGRITY-002" : "CP-INTEGRITY-001", location: "" }));
  if (c.ruleset.expired) out.push(ff.make({ ruleId: "CP-INTEGRITY-004", location: "" }));
  return out.filter((x): x is Finding => x !== null);
}

function capFindings(fs: Finding[], c: Ctx, ff: FindingFactory): { findings: Finding[]; capped: boolean } {
  const sorted = sortFindings(fs);
  if (sorted.length <= c.limits.maxFindings) return { findings: sorted, capped: false };
  const kept = sorted.slice(0, c.limits.maxFindings - 1);
  const f = ff.make({ ruleId: "CP-LIMIT-008", location: "" });
  if (f) kept.push(f);
  return { findings: kept, capped: true };
}

function riskOf(acc: Acc): ActionRisk {
  return {
    level: acc.level,
    tags: [...acc.tags].sort(),
    unanalyzable: acc.unanalyzableFlag,
    selfProtection: acc.selfProtection,
    reasons: [...acc.reasons, ...acc.unanalyzableReasons].slice(0, 20),
  };
}

export function errorDecision(t0: number, mode: SessionContext["policy"]["mode"] | undefined, risk?: ActionRisk): Decision {
  const r = risk ?? HIGH_RISK_UNKNOWN;
  const verdict: Verdict = r.level === "high-risk" ? "deny" : "warn"; // R12 / R11
  return {
    verdict,
    actionRisk: r,
    findings: [],
    rulesetVersion: "unknown",
    engineVersion: ENGINE_VERSION,
    degraded: true,
    degradedReasons: ["internal-error"],
    protectionDegraded: false,
    signals: [],
    suppressed: [],
    mode: mode === "strict" || mode === "autopilot" ? mode : "balanced",
    inputDigest: sha256Hex(""),
    elapsedMs: Math.max(0, now() - t0),
  };
}

// ── checkToolCall ────────────────────────────────────────────────────────

const EGRESS_TAGS: ActionTag[] = ["net.egress", "publish.public", "message.send"];
const ISSUERS: Record<string, string> = {
  "github-token": "github", "gitlab-token": "gitlab", "slack-token": "slack", "slack-webhook": "slack", "stripe-key": "stripe", "aws-access-key-id": "aws",
  "aws-secret-access-key": "aws", "gcp-api-key": "google", "openai-key": "openai", "anthropic-key": "anthropic", "azure-storage-key": "azure", "azure-conn-string": "azure",
};

function callFields(call: { serverId: string; toolName: string; arguments: unknown }): Field[] {
  const isShell = call.serverId === "builtin" && (call.toolName === "Bash" || call.toolName === "PowerShell");
  const fields = genericFields(call.arguments, "/arguments", "call.arg", "call.arg.key");
  if (isShell) for (const f of fields) if (f.pointer === "/arguments/command") f.role = "call.arg.command";
  return fields;
}

export function checkToolCallImpl(input: unknown, ctxIn: SessionContext, t0: number): Decision {
  const init0 = initMs();
  const c = validateCtx(ctxIn);
  if (!c) return errorDecision(t0, undefined);
  const ff = new FindingFactory(c.ruleset, c.evidenceMode);
  const ink = intake(input, c.limits);
  const issueFs = issueFindings(ink.issues, ff);
  const v = ink.value;
  const serverId = getString(v, "serverId");
  const toolName = getString(v, "toolName");
  if (ink.tooBig || serverId === undefined || toolName === undefined) {
    const d = errorDecision(t0, c.mode);
    const shape = ff.make({ ruleId: "CP-PARSE-010", location: "" });
    return { ...d, findings: sortFindings([...issueFs, ...(shape && !ink.tooBig ? [shape] : [])]), rulesetVersion: rulesetVersion(c.ruleset), degradedReasons: ink.tooBig ? ["CP-LIMIT-001"] : ["CP-PARSE-010"] };
  }
  const args = get(v, "arguments") ?? Object.create(null);
  const descriptor = isRecord(get(v, "descriptor")) ? (get(v, "descriptor") as ToolDef) : undefined;
  const call = { serverId, toolName, arguments: args };

  // Action risk.
  const tc = toolCtx(c);
  let acc: Acc;
  let contradiction = false;
  if (serverId === "builtin") acc = classifyBuiltin(toolName, args, tc);
  else {
    const p = classifyMcp(toolName, args, descriptor, tc);
    acc = p.acc;
    contradiction = p.contradiction;
  }
  const risk = riskOf(acc);

  // Layer 1 on the arguments.
  const scan = scanFields(callFields(call), "call", ff, c.ruleset.rules, c.limits, true);
  const findings: (Finding | null)[] = [...issueFs, ...scan.findings, ...integrityFindings(c, ff)];
  const cmdText = getString(args, "command") ?? getString(args, "query") ?? "";
  for (const cf of acc.findings) {
    findings.push(ff.make({ ruleId: cf.ruleId, location: cf.ruleId === "CP-EXFIL-040" ? "/arguments" : "/arguments", text: cmdText.slice(0, 2000), ...(cf.note && cf.ruleId === "CP-SHELL-001" ? {} : {}) }));
  }
  if (contradiction) findings.push(ff.make({ ruleId: "CP-CAP-002", location: "/descriptor/annotations" }));

  // Layer 2: correlation with secrets, destinations and session signals.
  const secretFindings = scan.findings.filter((f) => f.ruleId === "CP-SECRET-002" && f.confidence >= 0.5);
  const secretTypes = new Set<string>();
  for (const f of callFields(call)) for (const s of detectSecrets(f.text, f.keyName)) if (!s.example) secretTypes.add(s.type);
  const egress = risk.tags.some((t) => EGRESS_TAGS.includes(t));
  if (secretTypes.size > 0 && egress) findings.push(ff.make({ ruleId: "CP-EXFIL-031", location: secretFindings[0]?.location ?? "/arguments" }));
  const server = c.raw.servers?.find((s) => s.serverId === serverId);
  const issuerTags = server?.identity?.issuerTags;
  if (issuerTags && issuerTags.length > 0) {
    for (const t of secretTypes) {
      const iss = ISSUERS[t];
      if (iss && !issuerTags.includes(iss)) { findings.push(ff.make({ ruleId: "CP-EXFIL-050", location: secretFindings[0]?.location ?? "/arguments" })); break; }
    }
  }
  const sig = c.signals;
  const has = (k: SessionSignal["kind"]) => sig.some((s) => s.kind === k);
  const chain = (kinds: SessionSignal["kind"][]) => sig.filter((s) => kinds.includes(s.kind)).map((s) => `call #${s.atCall}`).slice(0, 6).join(", ");
  if (has("private-data-read") && has("untrusted-content-seen") && egress) {
    const why = `Earlier calls in this session (${chain(["private-data-read", "untrusted-content-seen"])}) read private data and untrusted content.`;
    findings.push(ff.make({ ruleId: "CP-FLOW-001", location: "/arguments", explanation: `${ff.rule("CP-FLOW-001")?.explanation ?? ""} ${why}`.trim() }));
    if (secretTypes.size > 0 || acc.sensitiveArgs) findings.push(ff.make({ ruleId: "CP-FLOW-002", location: "/arguments", explanation: `${ff.rule("CP-FLOW-002")?.explanation ?? ""} ${why}`.trim() }));
  }
  if (has("untrusted-content-seen") && (has("secret-seen") || has("sensitive-read")) && risk.tags.includes("net.egress")) {
    const why = `Chain: ${chain(["untrusted-content-seen", "secret-seen", "sensitive-read"])}.`;
    findings.push(ff.make({ ruleId: "CP-FLOW-003", location: "/arguments", explanation: `${ff.rule("CP-FLOW-003")?.explanation ?? ""} ${why}`.trim() }));
  }
  if (sig.some((s) => s.kind === "injection-seen" && s.mentionedTools.includes(toolName))) findings.push(ff.make({ ruleId: "CP-INJECT-021", location: "" }));

  // Limits / degraded.
  const degradedReasons: string[] = [];
  if (ink.degraded) degradedReasons.push(...new Set(ink.issues.map((i) => i.code)));
  if (scan.windowed) degradedReasons.push("CP-LIMIT-006");
  if (scan.decodeExhausted) { degradedReasons.push("CP-LIMIT-007"); findings.push(ff.make({ ruleId: "CP-LIMIT-007", location: "" })); }
  // One-time initialization (regex compiles, tables) doesn't count against the backstop.
  if (now() - t0 - (initMs() - init0) > c.limits.hardStopMs) { degradedReasons.push("CP-LIMIT-010"); findings.push(ff.make({ ruleId: "CP-LIMIT-010", location: "" })); }

  let fs = dedupe(findings);
  const sup = suppress(fs, c, ff);
  fs = sup.kept;
  const capped = capFindings(fs, c, ff);
  fs = capped.findings;
  const degraded = degradedReasons.length > 0;

  // Signals.
  const signals: SessionSignal[] = [];
  const at = c.callIndex;
  for (const label of new Set(acc.sensitive)) {
    signals.push({ kind: "sensitive-read", label, atCall: at });
    signals.push({ kind: "private-data-read", source: "sensitive-path", serverId, toolName, atCall: at });
  }
  for (const t of secretTypes) signals.push({ kind: "secret-seen", secretType: t, atCall: at });
  const ext = risk.tags.filter((t) => EGRESS_TAGS.includes(t));
  if (ext.length > 0) signals.push({ kind: "external-write", serverId, toolName, tags: ext, atCall: at });
  if (c.protectionDegraded) signals.push({ kind: "protection-degraded", reason: c.ruleset.degradedCause ?? (sig.find((s) => s.kind === "protection-degraded") as { reason: "tampered" | "downgrade" } | undefined)?.reason ?? "tampered", atCall: at });

  const out = decide({
    kind: "call", risk, findings: fs, degraded, protectionDegraded: c.protectionDegraded, ruleset: c.ruleset, policy: c.raw.policy,
    minConfidence: c.limits.minConfidenceForVerdict, serverId, toolName, remembered: Array.isArray(c.raw.remembered) ? c.raw.remembered : [],
  });
  return {
    verdict: out.verdict,
    actionRisk: risk,
    findings: fs,
    rulesetVersion: rulesetVersion(c.ruleset),
    engineVersion: ENGINE_VERSION,
    degraded,
    degradedReasons,
    protectionDegraded: c.protectionDegraded,
    signals,
    suppressed: sup.suppressed,
    mode: c.mode,
    ...(out.verdictBeforeMode !== undefined ? { verdictBeforeMode: out.verdictBeforeMode } : {}),
    inputDigest: digest(args),
    elapsedMs: Math.max(0, now() - t0),
  };
}

// ── checkToolResult ──────────────────────────────────────────────────────

const DIRECTIVES = new Set(["call", "run", "use", "invoke", "execute", "delete", "send", "now", "immediately", "must", "should", "always", "next", "then", "please"]);
const UNTRUSTED_BUILTINS = new Set(["WebFetch", "WebSearch"]);

export function checkToolResultImpl(input: unknown, ctxIn: SessionContext, t0: number): Decision {
  const c = validateCtx(ctxIn);
  if (!c) return errorDecision(t0, undefined, { ...HIGH_RISK_UNKNOWN, level: "read" });
  const ff = new FindingFactory(c.ruleset, c.evidenceMode);
  const ink = intake(input, c.limits);
  const issueFs = issueFindings(ink.issues, ff);
  const v = ink.value;
  const call = get(v, "call");
  const serverId = getString(call, "serverId");
  const toolName = getString(call, "toolName");
  if (ink.tooBig || serverId === undefined || toolName === undefined || !isRecord(v) || !Object.prototype.hasOwnProperty.call(v, "result")) {
    const d = errorDecision(t0, c.mode, { ...HIGH_RISK_UNKNOWN, level: "read" });
    return { ...d, findings: issueFs, rulesetVersion: rulesetVersion(c.ruleset), degradedReasons: ink.tooBig ? ["CP-LIMIT-001"] : ["CP-PARSE-010"] };
  }
  const result = get(v, "result");
  const args = get(call, "arguments") ?? Object.create(null);
  const tc = toolCtx(c);
  const acc = serverId === "builtin" ? classifyBuiltin(toolName, args, tc) : classifyMcp(toolName, args, isRecord(get(call, "descriptor")) ? (get(call, "descriptor") as ToolDef) : undefined, tc).acc;
  const risk = riskOf(acc);

  const fields = genericFields(result, "/result", "result.text", "result.key").filter((f) => f.kind === "string");
  const scan = scanFields(fields, "result", ff, c.ruleset.rules, c.limits, true);
  const findings: (Finding | null)[] = [...issueFs, ...scan.findings, ...integrityFindings(c, ff)];

  // CP-INJECT-020: a session tool named next to directive language.
  const sessionTools = new Map<string, boolean>();
  for (const s of c.raw.servers ?? []) for (const t of s.toolNames ?? []) sessionTools.set(t, (s.highRiskTools ?? []).includes(t));
  // Red team (Step 5): "use the GitHub tool to …" names a server, not a tool.
  for (const s of c.raw.servers ?? []) {
    if (s.serverId === serverId) continue;
    for (const n of [s.serverId, ...(s.identity?.issuerTags ?? [])]) if (typeof n === "string" && n.length >= 4) sessionTools.set(n, false);
  }
  const mentioned = new Set<string>();
  for (const f of fields) {
    const words = tokenize(f.text.slice(0, c.limits.maxFieldScanBytes));
    const lowerWords = new Set(words.map((w) => w.w.toLowerCase()));
    const directive = [...DIRECTIVES].some((d) => lowerWords.has(d));
    for (const name of sessionTools.keys()) {
      if (name.length >= 3 && directive && (f.text.includes(name) || (name.length >= 4 && lowerWords.has(name.toLowerCase())))) {
        mentioned.add(name);
        const at = Math.max(0, f.text.toLowerCase().indexOf(name.toLowerCase()));
        findings.push(ff.make({ ruleId: "CP-INJECT-020", location: f.pointer, text: f.text, start: at, end: at + name.length, ...(sessionTools.get(name) ? { severity: "critical" as const } : {}) }));
      }
    }
  }

  const degradedReasons: string[] = [];
  if (ink.degraded) degradedReasons.push(...new Set(ink.issues.map((i) => i.code)));
  if (scan.windowed) degradedReasons.push("CP-LIMIT-006");
  if (scan.decodeExhausted) degradedReasons.push("CP-LIMIT-007");
  let fs = dedupe(findings);
  const sup = suppress(fs, c, ff);
  fs = capFindings(sup.kept, c, ff).findings;
  const degraded = degradedReasons.length > 0;

  // Signals.
  const at = c.callIndex;
  const signals: SessionSignal[] = [];
  const injected = fs.some((f) => f.ruleId.startsWith("CP-INJECT-") && sevRank(f.severity) >= 3);
  if (injected) {
    for (const f of fields) for (const name of sessionTools.keys()) if (f.text.includes(name)) mentioned.add(name);
    signals.push({ kind: "injection-seen", serverId, mentionedTools: [...mentioned].sort(), atCall: at });
  }
  const secretTypes = new Set<string>();
  for (const f of fields) for (const s of detectSecrets(f.text.slice(0, c.limits.maxFieldScanBytes), f.keyName)) if (!s.example) secretTypes.add(s.type);
  for (const t of secretTypes) signals.push({ kind: "secret-seen", secretType: t, atCall: at });
  const untrusted = serverId !== "builtin" || UNTRUSTED_BUILTINS.has(toolName) || risk.tags.includes("net.egress") || degraded || injected;
  if (untrusted) signals.push({ kind: "untrusted-content-seen", serverId, toolName, atCall: at });
  if (c.protectionDegraded) signals.push({ kind: "protection-degraded", reason: c.ruleset.degradedCause ?? "tampered", atCall: at });

  const out = decide({
    kind: "result", risk, findings: fs, degraded, protectionDegraded: c.protectionDegraded, ruleset: c.ruleset, policy: c.raw.policy,
    minConfidence: c.limits.minConfidenceForVerdict, serverId, toolName, remembered: [],
  });
  let resultRewrite: Decision["resultRewrite"];
  if (out.verdict === "deny") {
    const top = fs[0];
    resultRewrite = { kind: "replace-with-notice", value: `[Glassbox withheld this tool output: ${top ? `${top.ruleId}. ${top.explanation}` : "it failed a check"}]` };
  } else if (c.mode === "strict" && fs.some((f) => f.category === "secret-exposure" && f.confidence >= 0.9)) {
    resultRewrite = { kind: "redact-secrets", value: redactValue(result, c.limits, 0.9).value };
  }
  return {
    verdict: out.verdict,
    actionRisk: risk,
    findings: fs,
    rulesetVersion: rulesetVersion(c.ruleset),
    engineVersion: ENGINE_VERSION,
    degraded,
    degradedReasons,
    protectionDegraded: c.protectionDegraded,
    signals,
    suppressed: sup.suppressed,
    mode: c.mode,
    ...(out.verdictBeforeMode !== undefined ? { verdictBeforeMode: out.verdictBeforeMode } : {}),
    inputDigest: digest(result),
    ...(resultRewrite ? { resultRewrite } : {}),
    elapsedMs: Math.max(0, now() - t0),
  };
}

// ── checkServerRequest ───────────────────────────────────────────────────

const DEFAULT_REQUEST: Record<ServerRequestKind, PolicyChoice> = { sampling: "deny", elicitation: "deny", roots: "deny", unknown: "deny", ping: "allow", notification: "allow" };

export function checkServerRequestImpl(input: unknown, ctxIn: SessionContext, t0: number): Decision {
  const c = validateCtx(ctxIn);
  if (!c) return errorDecision(t0, undefined);
  const ff = new FindingFactory(c.ruleset, c.evidenceMode);
  const ink = intake(input, c.limits);
  const v = ink.value;
  const serverId = getString(v, "serverId") ?? "unknown";
  const msg = get(v, "message");
  const method = getString(msg, "method") ?? "";
  const params = get(msg, "params");
  const kind: ServerRequestKind = method === "sampling/createMessage" ? "sampling" : method === "elicitation/create" ? "elicitation" : method === "roots/list" ? "roots" : method === "ping" ? "ping" : method.startsWith("notifications/") ? "notification" : "unknown";
  const fields: Field[] = [];
  if (kind === "sampling") {
    fields.push(...genericFields(get(params, "messages"), "/message/params/messages", "srvreq.sampling", "srvreq.key").filter((f) => f.kind === "string"));
    const sp = getString(params, "systemPrompt");
    if (sp !== undefined) fields.push({ pointer: "/message/params/systemPrompt", kind: "string", role: "srvreq.sampling", text: sp, keyName: "systemPrompt" });
  } else if (kind === "elicitation") {
    const m = getString(params, "message");
    if (m !== undefined) fields.push({ pointer: "/message/params/message", kind: "string", role: "srvreq.elicitation", text: m, keyName: "message" });
    fields.push(...genericFields(get(params, "requestedSchema"), "/message/params/requestedSchema", "srvreq.elicitation", "srvreq.elicitation.key"));
  } else {
    fields.push(...genericFields(params, "/message/params", "srvreq.other", "srvreq.key").filter((f) => f.kind === "string"));
  }
  const scan = scanFields(fields, "server-request", ff, c.ruleset.rules, c.limits, false);
  const findings: (Finding | null)[] = [...issueFindings(ink.issues, ff), ...scan.findings, ...integrityFindings(c, ff)];
  if (kind === "sampling") {
    const inc = getString(params, "includeContext");
    if (inc !== undefined && inc !== "none") findings.push(ff.make({ ruleId: "CP-SRVREQ-001", location: "/message/params/includeContext" }));
  }
  if (kind === "roots") findings.push(ff.make({ ruleId: "CP-SRVREQ-020", location: "/message" }));
  if (kind === "unknown") findings.push(ff.make({ ruleId: "CP-SRVREQ-030", location: "/message/method" }));
  if (method === "notifications/tools/list_changed") findings.push(ff.make({ ruleId: "CP-SRVREQ-040", location: "/message/method" }));

  const pol = c.raw.policy.serverRequests;
  let choice: PolicyChoice = DEFAULT_REQUEST[kind];
  if (kind === "sampling" || kind === "elicitation" || kind === "roots") {
    const per = pol?.perServer?.[serverId]?.[kind];
    const def = pol?.default?.[kind];
    const pick = per ?? def;
    if (pick === "allow" || pick === "ask" || pick === "deny") choice = pick;
  }
  const locked = kind === "unknown" || ink.tooBig;
  if (locked) choice = "deny";
  let fs = dedupe(findings);
  const sup = suppress(fs, c, ff);
  fs = capFindings(sup.kept, c, ff).findings;
  const risk: ActionRisk = kind === "sampling" || kind === "elicitation" ? { level: "high-risk", tags: ["exec.unknown"], unanalyzable: false, selfProtection: false, reasons: [`server request: ${kind}`] } : { level: "read", tags: [], unanalyzable: false, selfProtection: false, reasons: [`server request: ${kind}`] };
  const degraded = ink.degraded || scan.windowed;
  const out = decide({
    kind: "server-request", risk, findings: fs, degraded, protectionDegraded: c.protectionDegraded, ruleset: c.ruleset, policy: c.raw.policy,
    minConfidence: c.limits.minConfidenceForVerdict, serverId, toolName: method, remembered: [], requestVerdict: { verdict: choice as Verdict, locked },
  });
  return {
    verdict: out.verdict,
    actionRisk: risk,
    findings: fs,
    rulesetVersion: rulesetVersion(c.ruleset),
    engineVersion: ENGINE_VERSION,
    degraded,
    degradedReasons: degraded ? [...new Set(ink.issues.map((i) => i.code))] : [],
    protectionDegraded: c.protectionDegraded,
    signals: c.protectionDegraded ? [{ kind: "protection-degraded", reason: c.ruleset.degradedCause ?? "tampered", atCall: c.callIndex }] : [],
    suppressed: sup.suppressed,
    mode: c.mode,
    ...(out.verdictBeforeMode !== undefined ? { verdictBeforeMode: out.verdictBeforeMode } : {}),
    inputDigest: digest(msg),
    elapsedMs: Math.max(0, now() - t0),
  };
}
