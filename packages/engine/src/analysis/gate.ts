// The gate: checkToolCall / checkToolResult / checkServerRequest.
import { Acc } from "../action/acc.js";
import { normalizePath, pathCtxFrom, type PathCtx } from "../action/paths.js";
import { commandFiles, cronLines, desktopJob, JOB_LABEL, plistJob, psTaskJob, unitJob, type ScheduledJob } from "../action/schedule.js";
import { classifyBuiltin, classifyMcp, type ToolCtx } from "../action/tools.js";
import { snapshot } from "../intake/snapshot.js";
import { parseJsonStrict, type IntakeIssue } from "../intake/json.js";
import { resolveLimits } from "../limits.js";
import { decide } from "../policy/decide.js";
import { detectSecrets } from "../secrets/detect.js";
import { redactString, redactValue } from "../secrets/redact.js";
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

/**
 * The gate's time backstop: true once this call has run longer than
 * the limit, not counting one-time initialization (regex compiles, tables), which the first
 * call in a process pays and later calls don't.
 */
function overdue(t0: number, hardStopMs: number): () => boolean {
  const init0 = initMs();
  return () => now() - t0 - (initMs() - init0) > hardStopMs;
}

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
  const signals = all.filter((s) => s.kind === "protection-degraded" || s.kind === "scheduled-job" || callIndex - s.atCall <= limits.signalTtlCalls);
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

/** Why protection is degraded: the ruleset's own cause, else the reason carried by the session signal. */
function degradedReason(c: Ctx): "tampered" | "downgrade" | "internal-error" {
  if (c.ruleset.degradedCause) return c.ruleset.degradedCause;
  const s = c.signals.find((x) => x.kind === "protection-degraded");
  return s?.kind === "protection-degraded" ? s.reason : "tampered";
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
    // Q4 (rev 6): the verdict stays as is (warn for a result), but the session is marked
    // protection-degraded, so R16 makes the next high-risk call ask (deny in autopilot).
    // This signal never expires; atCall is unknown here and doesn't matter.
    protectionDegraded: true,
    signals: [{ kind: "protection-degraded", reason: "internal-error", atCall: 0 }],
    suppressed: [],
    mode: mode === "strict" || mode === "autopilot" ? mode : "balanced",
    inputDigest: sha256Hex(""),
    elapsedMs: Math.max(0, now() - t0),
  };
}

// ── checkToolCall ────────────────────────────────────────────────────────

const EGRESS_TAGS: ActionTag[] = ["net.egress", "publish.public", "message.send"];

/**
 * Q2 (rev 6): secrets precise enough to ask about when they go to a non-read tool
 * (CP-EXFIL-032). Test-mode keys, example values, JWTs and generic high-entropy strings
 * stay at their usual (warn) level.
 */
const LIVE_SECRET_TYPES = new Set([
  "private-key", "db-connection-string", "stripe-key", "github-token", "gitlab-token", "slack-token", "slack-webhook",
  "aws-access-key-id", "aws-secret-access-key", "gcp-api-key", "anthropic-key", "openai-key", "azure-storage-key", "azure-conn-string",
]);
const isLiveSecret = (s: { type: string; value: string; example: boolean }): boolean =>
  !s.example && LIVE_SECRET_TYPES.has(s.type) && !(s.type === "stripe-key" && (s.value.startsWith("sk_test_") || s.value.startsWith("rk_test_")));
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
  const scan = scanFields(callFields(call), "call", ff, c.ruleset.rules, c.limits, true, overdue(t0, c.limits.hardStopMs));
  const findings: (Finding | null)[] = [...issueFs, ...scan.findings, ...integrityFindings(c, ff)];
  const cmdText = getString(args, "command") ?? getString(args, "query") ?? "";
  for (const cf of acc.findings) {
    if (cf.ruleId === "CP-SELF-006") continue; // added below, one per job, with schedule and command
    findings.push(ff.make({ ruleId: cf.ruleId, location: cf.ruleId === "CP-EXFIL-040" ? "/arguments" : "/arguments", text: cmdText.slice(0, 2000), ...(cf.note && cf.ruleId === "CP-SHELL-001" ? {} : {}) }));
  }
  if (contradiction) findings.push(ff.make({ ruleId: "CP-CAP-002", location: "/descriptor/annotations" }));

  // Layer 2: correlation with secrets, destinations and session signals.
  const secretFindings = scan.findings.filter((f) => f.ruleId === "CP-SECRET-002" && f.confidence >= 0.5);
  const secretTypes = new Set<string>();
  let liveSecret = false;
  for (const f of callFields(call)) {
    for (const s of detectSecrets(f.text, f.keyName)) {
      if (!s.example) secretTypes.add(s.type);
      if (isLiveSecret(s)) liveSecret = true;
    }
  }
  if (liveSecret && risk.level !== "read") findings.push(ff.make({ ruleId: "CP-EXFIL-032", location: secretFindings[0]?.location ?? "/arguments" }));
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
  // Scheduled jobs (rev 9): show what runs, when, and the full command; record the files it runs.
  const jobs = acc.scheduledJobs.map((j) => enrichJob(j, toolName, args, cmdText, tc.pctx));
  for (const j of jobs) {
    findings.push(ff.make({ ruleId: "CP-SELF-006", location: "/arguments", text: cmdText.slice(0, 2000), explanation: jobExplanation(ff.rule("CP-SELF-006")?.explanation ?? "", j, toolName, args, cmdText, c.limits) }));
  }
  // Agent edits, moves or deletes of files an earlier, approved scheduled job runs (CP-SELF-007).
  const fold = (s: string) => (c.raw.caseInsensitiveFs ? s.toLowerCase() : s);
  for (const s of sig) {
    if (s.kind !== "scheduled-job" || !Array.isArray(s.files)) continue; // signals come from the caller
    const hit = s.files.filter((f): f is string => typeof f === "string").slice(0, 100).find((f) => acc.writes.some((w) => fold(w) === fold(f) || fold(f).startsWith(fold(w) + "/")));
    if (hit !== undefined) {
      findings.push(ff.make({ ruleId: "CP-SELF-007", location: "/arguments", text: hit, explanation: `This file runs as a scheduled job: ${hit} (${JOB_LABEL[s.job] ?? "scheduled job"}${s.schedule ? `, ${s.schedule}` : ""}; approved at call #${s.atCall}). Changing, moving or deleting it changes what the job runs.` }));
      break;
    }
  }

  // Any local file upload once the session has read untrusted content (rev 8, Q1).
  if (acc.uploads.length > 0 && has("untrusted-content-seen")) {
    findings.push(ff.make({ ruleId: "CP-EXFIL-036", location: "/arguments", explanation: `${ff.rule("CP-EXFIL-036")?.explanation ?? ""} Untrusted content: ${chain(["untrusted-content-seen"])}.`.trim() }));
  }

  // Limits / degraded.
  const degradedReasons: string[] = [];
  if (ink.degraded) degradedReasons.push(...new Set(ink.issues.map((i) => i.code)));
  if (scan.windowed) degradedReasons.push("CP-LIMIT-006");
  if (scan.decodeExhausted) { degradedReasons.push("CP-LIMIT-007"); findings.push(ff.make({ ruleId: "CP-LIMIT-007", location: "" })); }
  // One-time initialization (regex compiles, tables) doesn't count against the backstop.
  if (scan.timedOut || now() - t0 - (initMs() - init0) > c.limits.hardStopMs) { degradedReasons.push("CP-LIMIT-010"); findings.push(ff.make({ ruleId: "CP-LIMIT-010", location: "" })); }

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
  if (c.protectionDegraded) signals.push({ kind: "protection-degraded", reason: degradedReason(c), atCall: at });
  // A job that creates or changes something runs its files later. The caller keeps this signal
  // only if the call is approved and runs; it doesn't expire.
  for (const j of jobs) if (j.verb !== "removes" && j.files.length > 0) signals.push({ kind: "scheduled-job", job: j.kind, schedule: j.schedule, files: j.files, atCall: at });

  const out = decide({
    kind: "call", risk, findings: fs, degraded, protectionDegraded: c.protectionDegraded, ruleset: c.ruleset, policy: c.raw.policy,
    minConfidence: c.limits.minConfidenceForVerdict, serverId, toolName, remembered: Array.isArray(c.raw.remembered) ? c.raw.remembered.slice(0, 1000) : [],
    projectIdHash: typeof c.raw.projectIdHash === "string" ? c.raw.projectIdHash : undefined, sessionId: typeof c.raw.sessionId === "string" ? c.raw.sessionId : "",
    sessionGrants: Array.isArray(c.raw.sessionGrants) ? c.raw.sessionGrants.slice(0, 1000) : [],
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
  const late = overdue(t0, c.limits.hardStopMs);
  const scan = scanFields(fields, "result", ff, c.ruleset.rules, c.limits, true, late);
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
  // After a timeout, only fields the scan reached are examined (empty fields are never
  // scanned and can't match, so without a timeout this is every field).
  const reached = fields.filter((f) => scan.scans.has(f));
  for (const f of reached) {
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
  if (scan.timedOut || late()) { degradedReasons.push("CP-LIMIT-010"); findings.push(ff.make({ ruleId: "CP-LIMIT-010", location: "" })); }
  let fs = dedupe(findings);
  const sup = suppress(fs, c, ff);
  fs = capFindings(sup.kept, c, ff).findings;
  const degraded = degradedReasons.length > 0;

  // Signals.
  const at = c.callIndex;
  const signals: SessionSignal[] = [];
  const injected = fs.some((f) => f.ruleId.startsWith("CP-INJECT-") && sevRank(f.severity) >= 3);
  if (injected) {
    for (const f of reached) for (const name of sessionTools.keys()) if (f.text.includes(name)) mentioned.add(name);
    signals.push({ kind: "injection-seen", serverId, mentionedTools: [...mentioned].sort(), atCall: at });
  }
  const secretTypes = new Set<string>();
  for (const f of reached) {
    // Reuse the scan's secret results when the field was scanned whole (same text, same key).
    const memo = scan.scans.get(f)?.windowed === false ? scan.scans.get(f)?.secrets : undefined;
    for (const s of detectSecrets(f.text.slice(0, c.limits.maxFieldScanBytes), f.keyName, memo)) if (!s.example) secretTypes.add(s.type);
  }
  for (const t of secretTypes) signals.push({ kind: "secret-seen", secretType: t, atCall: at });
  const untrusted = serverId !== "builtin" || UNTRUSTED_BUILTINS.has(toolName) || risk.tags.includes("net.egress") || degraded || injected;
  if (untrusted) signals.push({ kind: "untrusted-content-seen", serverId, toolName, atCall: at });
  if (c.protectionDegraded) signals.push({ kind: "protection-degraded", reason: degradedReason(c), atCall: at });

  const out = decide({
    kind: "result", risk, findings: fs, degraded, protectionDegraded: c.protectionDegraded, ruleset: c.ruleset, policy: c.raw.policy,
    minConfidence: c.limits.minConfidenceForVerdict, serverId, toolName, remembered: [], sessionId: "", sessionGrants: [],
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
  const late = overdue(t0, c.limits.hardStopMs);
  const scan = scanFields(fields, "server-request", ff, c.ruleset.rules, c.limits, false, late);
  const timeFinding = scan.timedOut || late() ? ff.make({ ruleId: "CP-LIMIT-010", location: "" }) : null;
  if (timeFinding) scan.findings.push(timeFinding);
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
  const degraded = ink.degraded || scan.windowed || scan.timedOut;
  const out = decide({
    kind: "server-request", risk, findings: fs, degraded, protectionDegraded: c.protectionDegraded, ruleset: c.ruleset, policy: c.raw.policy,
    minConfidence: c.limits.minConfidenceForVerdict, serverId, toolName: method, remembered: [], sessionId: "", sessionGrants: [], requestVerdict: { verdict: choice as Verdict, locked },
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
    signals: c.protectionDegraded ? [{ kind: "protection-degraded", reason: degradedReason(c), atCall: c.callIndex }] : [],
    suppressed: sup.suppressed,
    mode: c.mode,
    ...(out.verdictBeforeMode !== undefined ? { verdictBeforeMode: out.verdictBeforeMode } : {}),
    inputDigest: digest(msg),
    elapsedMs: Math.max(0, now() - t0),
  };
}

// ── Scheduled jobs (rev 9) ───────────────────────────────────────────────

/** The text a tool call writes: Write content, Edit new_string, MultiEdit edits, MCP content. */
function writtenContent(args: unknown): string {
  if (!isRecord(args)) return "";
  const parts: string[] = [];
  for (const k of ["content", "new_string", "text", "body", "data"]) { const v = getString(args, k); if (v) parts.push(v); }
  const edits = get(args, "edits");
  if (Array.isArray(edits)) for (const e of edits.slice(0, 50)) { const v = getString(e, "new_string"); if (v) parts.push(v); }
  return parts.join("\n").slice(0, 200_000);
}

function enrichJob(j: ScheduledJob, toolName: string, args: unknown, cmdText: string, pctx: PathCtx): ScheduledJob {
  const content = writtenContent(args);
  const source = content || cmdText;
  let schedule = j.schedule;
  const files = [...j.files];
  const p = (j.path ?? "").toLowerCase();
  const fromDef = j.kind === "launchd" && j.path ? plistJob(source)
    : j.kind === "systemd" && j.path ? unitJob(source)
    : j.kind === "autostart" && j.path ? desktopJob(source)
    : j.kind === "task-scheduler" && schedule === null ? psTaskJob(cmdText)
    : null;
  if (fromDef) { schedule ??= fromDef.schedule; files.push(...fromDef.files); }
  if (j.kind === "cron" && j.verb !== "removes") {
    const period = ["hourly", "daily", "weekly", "monthly"].find((x) => p.includes(`/etc/cron.${x}/`));
    if (period) schedule ??= period;
    else {
      const lines = cronLines(source);
      if (lines.length > 0) { schedule ??= lines.map((l) => l.schedule).join("; "); for (const l of lines) files.push(...commandFiles(l.command)); }
    }
  }
  if (j.kind === "at" && files.length === 0) files.push(...commandFiles(quoted(cmdText)));
  if (j.kind === "boot-script") schedule ??= "at boot";
  if (j.kind === "startup-folder") schedule ??= "at login";
  const abs = (f: string) => normalizePath(f, pctx).path ?? f;
  void toolName;
  return { ...j, schedule, files: [...new Set(files.map(abs))].slice(0, 20) };
}

/** The text inside quotes (what `echo '…' | at …` runs). */
function quoted(text: string): string {
  const out: string[] = [];
  for (const q of ["'", '"']) {
    let i = text.indexOf(q);
    while (i >= 0 && out.length < 20) { const e = text.indexOf(q, i + 1); if (e < 0) break; out.push(text.slice(i + 1, e)); i = text.indexOf(q, e + 1); }
  }
  return out.join(" ");
}

function jobExplanation(base: string, j: ScheduledJob, toolName: string, args: unknown, cmdText: string, limits: Limits): string {
  const what = `${j.verb} a ${JOB_LABEL[j.kind]}${j.path ? ` (${j.path})` : ""}`;
  const runs = j.files.length > 0 ? j.files.join(", ") : "not visible in the call";
  const full = cmdText || `${toolName} ${getString(args, "file_path") ?? getString(args, "path") ?? ""}\n${writtenContent(args)}`.trim();
  const red = redactString(full, undefined, limits).text;
  const cap = 4000;
  const shown = red.length > cap ? `${red.slice(0, cap)} … (${red.length - cap} more characters)` : red;
  return `${base} This call ${what}. Schedule: ${j.schedule ?? "not visible in the call"}. Runs: ${runs}. Full command: ${shown}`;
}
