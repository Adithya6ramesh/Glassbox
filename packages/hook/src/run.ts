// One hook invocation: parse the payload, decide (PreToolUse) or record (everything else).
// Synchronous and total: any failure becomes the fail rule (PreToolUse) or exit 0 (others).
import * as v from "valibot";
import { checkToolCall, checkToolResult, parseClaudeCodeToolName, redact, type Decision, type SessionSignal } from "@glassbox-ai/engine";
import { exitCodeFromFailure, isPlainRecord, matchesKnownResponseShape, parseHookInput, PostToolUseOutput, type HookInput, type KnownHookEvent, type Outcome } from "@glassbox-ai/protocol";
import { buildContext, loadConfig, loadRemembered, projectOf, type Config, type HookEnv } from "./context.js";
import { eventCallId, eventLine, findingsOf, inputDigest, toolInfo, type EventBase } from "./events.js";
import { failReply, type FailCause } from "./failrules.js";
import { blockingReasonOf, EMPTY_REPLY, preReply, type Reply } from "./reply.js";
import crypto from "node:crypto";
import { Store, type PendingDecision } from "./store.js";
import { summarize } from "./summary.js";

/** The event name on the hook's command line (`glassbox-hook <event>`). */
export const EVENT_ARGS = {
  pre: "PreToolUse",
  post: "PostToolUse",
  "post-failure": "PostToolUseFailure",
  "post-batch": "PostToolBatch",
  "permission-request": "PermissionRequest",
  "user-prompt": "UserPromptSubmit",
  stop: "Stop",
  "subagent-start": "SubagentStart",
  "subagent-stop": "SubagentStop",
  "session-start": "SessionStart",
  "session-end": "SessionEnd",
} as const satisfies Record<string, KnownHookEvent>;
export type HookEventArg = keyof typeof EVENT_ARGS;

export function isEventArg(x: unknown): x is HookEventArg {
  return typeof x === "string" && Object.hasOwn(EVENT_ARGS, x);
}

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as const;

/**
 * The engine's time limit per check (owner decision 2026-11-25). The engine's own default (100 ms)
 * is for other callers; a hook process is always cold, and a slow or busy machine must not turn
 * normal calls into degraded ones. Huge or pathological inputs still hit these limits.
 */
export const HARD_STOP_MS = Object.freeze({ pre: 750, post: 1500 });

/** The reason Claude (deny) or the user (ask) reads. Secrets in it are masked. */
export function reasonFor(d: Decision): string {
  const top = [...d.findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])[0];
  const body = top?.explanation
    ?? (d.actionRisk.unanalyzable ? "it couldn't fully analyze this action." : d.actionRisk.reasons[0])
    ?? "this action needs your approval.";
  const prefix = d.verdict === "deny" ? "Blocked by Glassbox: " : "Glassbox: ";
  let text = prefix + body;
  try {
    const r = redact(text);
    if (typeof r.value === "string") text = r.value;
  } catch {
    text = prefix + "see glassbox tail for details.";
  }
  return text.length <= 500 ? text : `${text.slice(0, 499)}…`;
}

const appliedAsOf = (verdict: Decision["verdict"], cfg: Config): PendingDecision["appliedAs"] =>
  verdict === "deny" ? "deny" : verdict === "ask" ? "ask" : verdict === "warn" && cfg.flags.unverifiedHookOutputs ? "allow+note" : "allow";

function toolCall(name: string, args: Record<string, unknown>, agentType: string | undefined) {
  const t = name.startsWith("mcp__") ? parseClaudeCodeToolName(name) : { serverId: "builtin", toolName: name };
  return { serverId: t.serverId, toolName: t.toolName, arguments: args, ...(agentType ? { agent: agentType } : {}) };
}

interface Session {
  input: HookInput;
  store: Store;
  config: Config;
  base: EventBase;
}

/**
 * What logs/hook.log records for this call: event, ids, verdicts, outcomes, rule ids, timings,
 * degraded reasons. Never content (no commands, paths, inputs or outputs).
 */
let callLog: Record<string, unknown> = {};
const note = (fields: Record<string, unknown>) => { callLog = { ...callLog, ...fields }; };

function openSession(input: HookInput, env: HookEnv): Session & { remembered: ReturnType<typeof loadRemembered> } {
  const store = new Store(env.glassboxHome);
  const fixed = store.fixPermissions();
  if (fixed.length > 0) note({ "fixed-permissions": fixed });
  const config = loadConfig(store);
  const remembered = loadRemembered(store);
  const project = projectOf(input.cwd, env, store);
  const degradedReasons = [...config.degradedReasons, ...remembered.degradedReasons, ...(store.saltUnsafe ? ["salt-unsafe"] : [])];
  if (degradedReasons.length > 0) note({ degraded: degradedReasons });
  return {
    input, store, config, remembered,
    base: { sessionId: input.session_id, mode: config.mode, project, degradedReasons, startedAtMs: env.startedAtMs },
  };
}

/**
 * A failure leaves a trace: a "degraded" event saying why, best effort. Only plain fields are
 * taken from a broken payload (a hostile session_id is hashed by eventLine, never used as a path).
 */
export function recordFailure(env: HookEnv, arg: string, cause: string, text: string | null, reply: Reply): void {
  try {
    let raw: unknown;
    try {
      raw = text ? JSON.parse(text) : undefined;
    } catch {
      raw = undefined;
    }
    const r = isPlainRecord(raw) ? raw : {};
    const str = (k: string, max: number) => (typeof r[k] === "string" && (r[k] as string).length > 0 && (r[k] as string).length <= max ? (r[k] as string) : undefined);
    const store = new Store(env.glassboxHome);
    const config = loadConfig(store);
    const cwd = str("cwd", 4096);
    const project = cwd ? projectOf(cwd, env, store) : { idHash: crypto.createHmac("sha256", store.salt()).update("").digest("hex"), label: "unknown" };
    const tool = str("tool_name", 256);
    const reasons = [cause, ...config.degradedReasons];
    store.spool([eventLine({ sessionId: str("session_id", 256) ?? "unknown", mode: config.mode, project, degradedReasons: reasons, startedAtMs: env.startedAtMs }, {
      kind: "degraded", tool: tool ? toolInfo(tool) : undefined, appliedAs: blockingReasonOf(reply) ? "deny" : "allow",
    })].filter((l): l is string => l !== null));
    note({ event: arg, degraded: reasons });
  } catch {
    // Best effort: the reply stands.
  }
}

/** Append this call's line to logs/hook.log. Best effort. */
export function writeCallLog(env: HookEnv, startedMs: number): void {
  try {
    new Store(env.glassboxHome).log({ ts: new Date(Date.now()).toISOString(), ...callLog, ms: Math.round((performance.now() - startedMs) * 10) / 10 });
  } catch {
    // A log line is never worth failing a call.
  }
}

function parse(text: string, expected: KnownHookEvent): { ok: true; input: HookInput } | { ok: false; toolName: unknown } {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, toolName: undefined };
  }
  const r = parseHookInput(raw, expected);
  if (r.ok && r.known) return { ok: true, input: r.input };
  return { ok: false, toolName: isPlainRecord(raw) ? raw["tool_name"] : undefined };
}

/** Run one hook event. Never throws. */
export function runHook(arg: string, text: string, env: HookEnv): Reply {
  if (!isEventArg(arg)) return EMPTY_REPLY;
  const started = performance.now();
  callLog = { event: arg };
  let toolName: unknown;
  let reply: Reply;
  try {
    const p = parse(text, EVENT_ARGS[arg]);
    if (!p.ok) {
      toolName = p.toolName;
      reply = failReply(arg, toolName, "invalid input");
      recordFailure(env, arg, "hook-invalid-input", text, reply);
    } else {
      toolName = "tool_name" in p.input ? p.input.tool_name : undefined;
      reply = handle(arg, p.input, env);
    }
  } catch {
    reply = failReply(arg, toolName, "internal error" satisfies FailCause);
    recordFailure(env, arg, "hook-internal-error", text, reply);
  }
  writeCallLog(env, started);
  return reply;
}

function handle(arg: HookEventArg, input: HookInput, env: HookEnv): Reply {
  switch (input.hook_event_name) {
    case "PreToolUse": return handlePre(input, env);
    case "PostToolUse": return handlePost(input, env);
    case "PostToolUseFailure": return record(() => handleFailure(input, env));
    case "PostToolBatch": return record(() => handleBatch(input, env));
    case "Stop": return record(() => closeOpen(openSession(input, env), (p) => p.agentId === null, "session_stop"));
    case "UserPromptSubmit": return record(() => closeOpen(openSession(input, env), (p) => p.agentId === null));
    case "SubagentStop": return record(() => closeOpen(openSession(input, env), (p) => p.agentId === input.agent_id));
    case "SessionEnd": return record(() => closeOpen(openSession(input, env), () => true, "session_end"));
    case "SessionStart": return record(() => {
      const s = openSession(input, env);
      const pruned = s.store.pruneSessions(Date.now());
      if (pruned > 0) note({ pruned });
      spool(s, [eventLine(s.base, { kind: "session_start" })]);
    });
    case "PermissionRequest": return record(() => {
      const s = openSession(input, env);
      note({ claudeCodeAsked: s.store.markClaudeCodeAsked(input.session_id, input.tool_name, inputDigest(input.tool_input), input.agent_id ?? null) });
    });
    default:
      void arg;
      return EMPTY_REPLY;
  }
}

/** Recording never blocks and never fails the hook. */
function record(fn: () => void): Reply {
  try {
    fn();
  } catch {
    // Recording is best effort; Claude Code's action is unaffected.
  }
  return EMPTY_REPLY;
}

function spool(s: Session, lines: (string | null)[]): void {
  const r = s.store.spool(lines.filter((l): l is string => l !== null));
  if (r !== "written") note({ spool: r });
}

function handlePre(input: Extract<HookInput, { hook_event_name: "PreToolUse" }>, env: HookEnv): Reply {
  const s = openSession(input, env);
  const ctx = buildContext({
    sessionId: input.session_id, cwd: input.cwd, toolInput: input.tool_input, env, store: s.store, config: s.config,
    projectIdHash: s.base.project.idHash, remembered: s.remembered.rules, hardStopMs: HARD_STOP_MS.pre,
  });
  const d = checkToolCall(toolCall(input.tool_name, input.tool_input, input.agent_type), ctx);
  const reason = reasonFor(d);
  const alert = d.protectionDegraded ? "Glassbox: partially protected (rule cache rejected). Run glassbox doctor." : undefined;
  const reply = preReply({ verdict: d.verdict, reason, ...(alert ? { alert } : {}) }, s.config.flags);

  // Recording must never change the decision above.
  try {
    const appliedAs = appliedAsOf(d.verdict, s.config);
    const summary = summarize(input.tool_name, input.tool_input, { cwd: ctx.cwd, homeDir: env.homeDir, caseInsensitive: ctx.caseInsensitiveFs });
    const actionRisk = { level: d.actionRisk.level, tags: [...d.actionRisk.tags], unanalyzable: d.actionRisk.unanalyzable };
    s.store.appendSignals(input.session_id, d.signals.filter((g) => g.kind !== "scheduled-job"));
    s.store.putPending(input.session_id, {
      callId: input.tool_use_id, toolName: input.tool_name, agentId: input.agent_id ?? null, verdict: d.verdict, appliedAs, reason,
      inputDigest: inputDigest(input.tool_input), summary, actionRisk,
      deferredSignals: d.signals.filter((g) => g.kind === "scheduled-job"), createdAt: new Date(Date.now()).toISOString(),
    });
    const degradedReasons = [...s.base.degradedReasons, ...(d.degraded ? d.degradedReasons : [])];
    note({
      callId: eventCallId(input.tool_use_id), verdict: d.verdict, appliedAs, ruleIds: d.findings.map((f) => f.ruleId).slice(0, 20),
      engineMs: Math.round(d.elapsedMs * 10) / 10, ...(degradedReasons.length > 0 ? { degraded: degradedReasons } : {}),
    });
    spool(s, [eventLine({ ...s.base, degradedReasons }, {
      kind: "tool_pre", callId: eventCallId(input.tool_use_id), tool: toolInfo(input.tool_name), verdict: d.verdict, appliedAs,
      actionRisk, findings: findingsOf(d), summary, engineMs: d.elapsedMs, rulesetVersion: d.rulesetVersion,
    })]);
  } catch {
    // The reply stands; the event is lost.
  }
  return reply;
}

function postEvent(s: Session, p: PendingDecision | null, toolName: string, callId: string, outcome: Outcome, extra: {
  summary?: Record<string, unknown>; findings?: ReturnType<typeof findingsOf>; resultRewriteApplied?: boolean; engineMs?: number;
  engineDegradedReasons?: readonly string[];
} = {}): string | null {
  return eventLine(s.base, {
    kind: "tool_post", callId: eventCallId(callId), outcome, tool: toolInfo(toolName),
    verdict: p?.verdict, appliedAs: p?.appliedAs, actionRisk: p?.actionRisk,
    summary: { ...(p?.summary ?? {}), ...(extra.summary ?? {}) },
    findings: extra.findings, resultRewriteApplied: extra.resultRewriteApplied, engineMs: extra.engineMs,
    engineDegradedReasons: extra.engineDegradedReasons,
  });
}

/** CP-HOOK-001: the input that ran differs from the input Glassbox checked (another hook rewrote it). */
function rewriteFinding(p: PendingDecision | null, toolInput: Record<string, unknown>) {
  if (p === null || p.inputDigest === inputDigest(toolInput)) return [];
  return [{ ruleId: "CP-HOOK-001", category: "integrity", severity: "high" as const, location: "/tool_input" }];
}

function handlePost(input: Extract<HookInput, { hook_event_name: "PostToolUse" }>, env: HookEnv): Reply {
  let reply: Reply = EMPTY_REPLY;
  try {
    const s = openSession(input, env);
    const p = s.store.takePending(input.session_id, input.tool_use_id);
    const ctx = buildContext({
      sessionId: input.session_id, cwd: input.cwd, toolInput: input.tool_input, env, store: s.store, config: s.config,
      projectIdHash: s.base.project.idHash, remembered: s.remembered.rules, hardStopMs: HARD_STOP_MS.post,
    });
    const call = toolCall(input.tool_name, input.tool_input, input.agent_type);
    const d = checkToolResult({ call, result: input.tool_response }, ctx);
    s.store.appendSignals(input.session_id, [...d.signals, ...(p?.deferredSignals ?? [])] as SessionSignal[]);

    let resultRewriteApplied: boolean | undefined;
    if (d.resultRewrite) {
      resultRewriteApplied = false;
      // TODO-VERIFY output: only behind the flag, and only for a verified response shape.
      if (s.config.flags.unverifiedHookOutputs && matchesKnownResponseShape(input.tool_name, d.resultRewrite.value)) {
        const out = { hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: d.resultRewrite.value } };
        if (v.is(PostToolUseOutput, out)) {
          reply = { exitCode: 0, stdout: JSON.stringify(out), stderr: "" };
          resultRewriteApplied = true;
        }
      }
    }
    const findings = [...rewriteFinding(p, input.tool_input), ...findingsOf(d)];
    note({ callId: eventCallId(input.tool_use_id), outcome: "ran", ruleIds: findings.map((f) => f.ruleId).slice(0, 20), engineMs: Math.round(d.elapsedMs * 10) / 10 });
    spool(s, [postEvent(s, p, input.tool_name, input.tool_use_id, "ran", {
      ...(p ? {} : { summary: summarize(input.tool_name, input.tool_input, { cwd: ctx.cwd, homeDir: env.homeDir, caseInsensitive: ctx.caseInsensitiveFs }) }),
      ...(findings.length ? { findings } : {}),
      ...(resultRewriteApplied !== undefined ? { resultRewriteApplied } : {}),
      engineMs: d.elapsedMs,
      ...(d.degraded ? { engineDegradedReasons: d.degradedReasons } : {}),
    })]);
  } catch {
    return reply;
  }
  return reply;
}

function handleFailure(input: Extract<HookInput, { hook_event_name: "PostToolUseFailure" }>, env: HookEnv): void {
  const s = openSession(input, env);
  const p = s.store.takePending(input.session_id, input.tool_use_id);
  // The command started, so deferred signals (scheduled jobs) are kept: stricter, never looser.
  if (p?.deferredSignals.length) s.store.appendSignals(input.session_id, p.deferredSignals);
  const code = ["Bash", "PowerShell", "Monitor"].includes(input.tool_name) ? exitCodeFromFailure(input.error) : null;
  const summary = {
    ...(p ? {} : summarize(input.tool_name, input.tool_input, { cwd: input.cwd, homeDir: env.homeDir, caseInsensitive: env.platform !== "linux" })),
    ...(code !== null ? { exitCode: code } : {}),
    ...(input.is_interrupt ? { interrupted: true } : {}),
  };
  const findings = rewriteFinding(p, input.tool_input);
  note({ callId: eventCallId(input.tool_use_id), outcome: "failed" });
  spool(s, [postEvent(s, p, input.tool_name, input.tool_use_id, "failed", { summary, ...(findings.length ? { findings } : {}) })]);
}

/** A call that never ran: the PostToolBatch entry is the only trace, carrying the exact text Claude saw. */
export function batchOutcome(p: Pick<PendingDecision, "appliedAs" | "reason">, text: string): Outcome {
  if (p.appliedAs === "deny") return "blocked";
  if (p.appliedAs === "ask") return text === p.reason ? "blocked-no-one-to-ask" : "asked-not-run";
  return "refused-not-run";
}

function handleBatch(input: Extract<HookInput, { hook_event_name: "PostToolBatch" }>, env: HookEnv): void {
  const s = openSession(input, env);
  const lines: (string | null)[] = [];
  for (const c of input.tool_calls) {
    if (typeof c.tool_response !== "string") continue; // it ran: PostToolUse already recorded it
    const p = s.store.takePending(input.session_id, c.tool_use_id);
    if (p === null) continue;
    lines.push(postEvent(s, p, c.tool_name, c.tool_use_id, batchOutcome(p, c.tool_response)));
  }
  if (lines.length > 0) note({ closed: lines.length });
  spool(s, lines);
}

/** No event follows an unanswered or refused ask in an interactive session: close what is still open. */
export function closeOutcome(p: Pick<PendingDecision, "appliedAs" | "claudeCodeAsked">): Outcome {
  if (p.appliedAs === "deny") return "blocked";
  // Asked by Glassbox, or by Claude Code's own prompt (PermissionRequest), and nothing followed.
  if (p.appliedAs === "ask" || p.claudeCodeAsked === true) return "asked-not-run";
  return "unknown";
}

function closeOpen(s: Session, match: (p: PendingDecision) => boolean, kind?: "session_stop" | "session_end"): void {
  const open = s.store.takeAllPending(s.input.session_id, match);
  const lines = open.map((p) => postEvent(s, p, p.toolName, p.callId, closeOutcome(p)));
  if (open.length > 0) note({ closed: open.length });
  if (kind) lines.push(eventLine(s.base, { kind }));
  spool(s, lines);
}
