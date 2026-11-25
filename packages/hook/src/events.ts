// Building spool events (SpoolEvent = the protocol envelope without deviceSeq).
import crypto from "node:crypto";
import * as v from "valibot";
import { ENGINE_VERSION, parseClaudeCodeToolName, type Decision } from "@glassbox-ai/engine";
import { CallId, SessionId, SpoolEvent, type Outcome } from "@glassbox-ai/protocol";

export const HOOK_VERSION = "0.0.0";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** ULID: 48-bit millisecond time + 80 random bits, Crockford base32. */
export function ulid(nowMs: number = Date.now()): string {
  let t = Math.max(0, Math.floor(nowMs));
  let time = "";
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD.charAt(t % 32) + time;
    t = Math.floor(t / 32);
  }
  const rnd = crypto.randomBytes(16);
  let rand = "";
  for (let i = 0; i < 16; i++) rand += CROCKFORD.charAt(rnd.readUInt8(i) % 32);
  return time + rand;
}

/** Session id as the protocol accepts it (UUIDs pass unchanged; anything else is hashed). */
export function eventSessionId(id: string): string {
  return v.is(SessionId, id) ? id : crypto.createHash("sha256").update(String(id)).digest("hex");
}

export function eventCallId(id: string): string | undefined {
  return v.is(CallId, id) ? id : undefined;
}

export function toolInfo(name: string): { name: string; server?: string; builtin: boolean } {
  if (!name.startsWith("mcp__")) return { name: name.slice(0, 256), builtin: true };
  const t = parseClaudeCodeToolName(name);
  return { name: t.toolName.slice(0, 256) || name.slice(0, 256), server: t.serverId.slice(0, 128), builtin: false };
}

/** Findings without evidence (evidence can hold user content; metadata-only by default). */
export function findingsOf(d: Pick<Decision, "findings">): { ruleId: string; category: string; severity: "info" | "low" | "medium" | "high" | "critical"; location: string }[] {
  return d.findings.slice(0, 100).map((f) => ({
    ruleId: f.ruleId.slice(0, 32),
    category: f.category,
    severity: f.severity,
    location: (f.location || "/").slice(0, 256),
  }));
}

export interface EventBase {
  sessionId: string;
  mode: "autopilot" | "balanced" | "strict";
  project: { idHash: string; label: string };
  degradedReasons: string[];
  startedAtMs?: number | undefined;
}

export interface EventFields {
  kind: "session_start" | "tool_pre" | "tool_post" | "session_stop" | "session_end" | "degraded" | "self_protection";
  callId?: string | undefined;
  outcome?: Outcome | undefined;
  resultRewriteApplied?: boolean | undefined;
  tool?: { name: string; server?: string; builtin: boolean } | undefined;
  verdict?: "allow" | "warn" | "ask" | "deny" | undefined;
  appliedAs?: "allow" | "deny" | "ask" | "allow+note" | "feedback" | undefined;
  actionRisk?: { level: "read" | "write-reversible" | "high-risk"; tags: string[]; unanalyzable: boolean } | undefined;
  findings?: ReturnType<typeof findingsOf> | undefined;
  summary?: Record<string, unknown> | undefined;
  engineMs?: number | undefined;
  rulesetVersion?: string | undefined;
}

/** A validated spool line, or null if it doesn't fit the schema (it is then not written). */
export function eventLine(base: EventBase, f: EventFields): string | null {
  const degradedReasons = [...new Set(base.degradedReasons)].slice(0, 20);
  const raw: Record<string, unknown> = {
    v: 1,
    eventId: ulid(),
    ts: new Date(Date.now()).toISOString(),
    sessionId: eventSessionId(base.sessionId),
    kind: f.kind,
    summary: f.summary ?? {},
    timing: {
      totalMs: Math.max(0, performance.now()),
      engineMs: Math.max(0, f.engineMs ?? 0),
      ...(base.startedAtMs !== undefined ? { startupMs: Math.max(0, base.startedAtMs) } : {}),
    },
    versions: { plugin: HOOK_VERSION, engine: ENGINE_VERSION, ruleset: (f.rulesetVersion ?? "baseline").slice(0, 100) || "baseline" },
    mode: base.mode,
    degraded: degradedReasons.length > 0,
    ...(degradedReasons.length > 0 ? { degradedReasons } : {}),
    project: base.project,
  };
  for (const k of ["callId", "outcome", "resultRewriteApplied", "tool", "verdict", "appliedAs", "actionRisk", "findings"] as const) {
    if (f[k] !== undefined) raw[k] = f[k];
  }
  const r = v.safeParse(SpoolEvent, raw);
  return r.success ? JSON.stringify(r.output) : null;
}

/** SHA-256 of the input with object keys sorted, so key order doesn't count as a change. */
export function inputDigest(value: unknown): string {
  const seen = new WeakSet<object>();
  const canon = (x: unknown): unknown => {
    if (x === null || typeof x !== "object") return x;
    if (seen.has(x)) return "[cycle]";
    seen.add(x);
    if (Array.isArray(x)) return x.map(canon);
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(x).sort()) Object.defineProperty(o, k, { value: canon((x as Record<string, unknown>)[k]), enumerable: true });
    return o;
  };
  return crypto.createHash("sha256").update(JSON.stringify(canon(value)) ?? "").digest("hex");
}
