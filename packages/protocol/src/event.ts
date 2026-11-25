// Glassbox event envelope (v1) and the upload batch.
//
// The hook writes envelopes to the local spool; the uploader re-validates them with these
// schemas before sending; the server validates them again. Object schemas strip unknown
// fields, so a field that isn't in the schema (for example a tenant id or a token) is
// never passed on.
//
// Content is metadata-only by default. `summary` carries redacted template inputs; full
// input/output appears only in `content`, which is opt-in and already redacted.
import * as v from "valibot";

/** Size limits, in UTF-8 bytes. */
export const LIMITS = {
  eventBytes: 64 * 1024,
  eventWithContentBytes: 128 * 1024,
  contentFieldBytes: 64 * 1024,
  batchEvents: 500,
  batchBytes: 1024 * 1024,
  findings: 100,
  tags: 64,
} as const;

const Text = (max: number) => v.pipe(v.string(), v.minLength(1), v.maxLength(max));

/** ULID (Crockford base32, 26 chars, first char 0-7). Also the idempotency key. */
export const EventId = v.pipe(v.string(), v.regex(/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/, "not a ULID"));

/** RFC 3339 timestamp with seconds and an explicit offset. */
export const Timestamp = v.pipe(
  v.string(),
  v.regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/, "not an RFC 3339 timestamp"),
  v.check((s) => !Number.isNaN(Date.parse(s)), "not a real date"),
);

/** Claude Code session id. UUID in practice; only a safe character set is enforced. */
export const SessionId = v.pipe(v.string(), v.regex(/^[A-Za-z0-9-]{1,128}$/, "bad session id"));

/**
 * A path in a summary: project-relative, or `~/…/<basename>` for a file outside the
 * project. Absolute paths, drive letters, UNC paths and `..` segments are rejected,
 * because they leak user names and folder layout in the metadata-only default.
 */
export const SummaryPath = v.pipe(
  Text(512),
  v.check((p) => !/^([A-Za-z]:|[\\/]|~[^/\\])/.test(p), "absolute path"),
  v.check((p) => !p.split(/[\\/]/).includes(".."), "'..' segment"),
  v.check((p) => !/[\u0000-\u001f]/.test(p), "control character"),
);

/** Template inputs. Every field is already redacted by the hook. */
export const SummaryFields = v.object({
  /** Shell: command name + subcommand + flags only, never argument values. */
  cmd: v.optional(Text(200)),
  /** Shell exit code, when the payload has one (only failed commands carry one). */
  exitCode: v.optional(v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(255))),
  interrupted: v.optional(v.boolean()),
  path: v.optional(SummaryPath),
  /** Read/Glob/Grep: the pattern's length only, never its text. */
  patternLength: v.optional(v.pipe(v.number(), v.integer(), v.minValue(0))),
  /** Network tools: host only, no path or query. */
  host: v.optional(v.pipe(Text(253), v.regex(/^[A-Za-z0-9.-]+(:\d{1,5})?$/, "host only"))),
  /** MCP tools. */
  server: v.optional(Text(128)),
  toolName: v.optional(Text(256)),
  /** Denies: the rule ids that fired. */
  ruleIds: v.optional(v.pipe(v.array(Text(32)), v.maxLength(20))),
});

const Finding = v.object({
  ruleId: Text(32),
  category: Text(64),
  severity: v.picklist(["info", "low", "medium", "high", "critical"]),
  location: Text(256),
  evidence: v.optional(v.pipe(v.string(), v.maxLength(200))),
});

const utf8 = (s: string) => new TextEncoder().encode(s).length;
const MaxBytes = (n: number) => v.check((s: string) => utf8(s) <= n, `over ${n} bytes`);

const TOOL_KINDS = ["tool_pre", "tool_post"] as const;

const EnvelopeObject = v.object({
  v: v.literal(1),
  eventId: EventId,
  deviceSeq: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
  ts: Timestamp,
  sessionId: SessionId,
  kind: v.picklist(["session_start", "tool_pre", "tool_post", "session_stop", "session_end", "heartbeat", "degraded", "self_protection"]),
  tool: v.optional(v.object({ name: Text(256), server: v.optional(Text(128)), builtin: v.boolean() })),
  verdict: v.optional(v.picklist(["allow", "warn", "ask", "deny"])),
  /** What was actually returned to Claude Code (can differ from the verdict). */
  appliedAs: v.optional(v.picklist(["allow", "deny", "ask", "allow+note", "feedback"])),
  actionRisk: v.optional(v.object({
    level: v.picklist(["read", "write-reversible", "high-risk"]),
    tags: v.pipe(v.array(Text(64)), v.maxLength(LIMITS.tags)),
    unanalyzable: v.boolean(),
  })),
  findings: v.optional(v.pipe(v.array(Finding), v.maxLength(LIMITS.findings))),
  summary: SummaryFields,
  content: v.optional(v.object({
    input: v.optional(v.pipe(v.string(), MaxBytes(LIMITS.contentFieldBytes))),
    output: v.optional(v.pipe(v.string(), MaxBytes(LIMITS.contentFieldBytes))),
    truncated: v.boolean(),
  })),
  timing: v.object({
    totalMs: v.pipe(v.number(), v.minValue(0)),
    engineMs: v.pipe(v.number(), v.minValue(0)),
    startupMs: v.optional(v.pipe(v.number(), v.minValue(0))),
  }),
  versions: v.object({ plugin: Text(50), engine: Text(50), ruleset: Text(100) }),
  mode: v.picklist(["autopilot", "balanced", "strict"]),
  degraded: v.boolean(),
  degradedReasons: v.optional(v.pipe(v.array(Text(64)), v.maxLength(20))),
  project: v.object({
    /** HMAC-SHA256 (hex) of the project's real path under a device-local salt. */
    idHash: v.pipe(v.string(), v.regex(/^[0-9a-f]{64}$/, "not a hex SHA-256")),
    /** Display label (folder basename), not a path. */
    label: v.pipe(Text(64), v.check((s) => !/[\\/]/.test(s), "label must not be a path")),
  }),
});

export const EventEnvelope = v.pipe(
  EnvelopeObject,
  v.check((e) => !(TOOL_KINDS as readonly string[]).includes(e.kind) || e.tool !== undefined, "tool events need `tool`"),
  v.check((e) => e.degraded || e.degradedReasons === undefined, "degradedReasons without degraded"),
  v.check(
    (e) => utf8(JSON.stringify(e)) <= (e.content === undefined ? LIMITS.eventBytes : LIMITS.eventWithContentBytes),
    "event too large",
  ),
);
export type EventEnvelope = v.InferOutput<typeof EventEnvelope>;

/**
 * POST /events body. The tenant and device come from the device token on the server,
 * never from the body: unknown fields such as `tenantId` are stripped.
 */
export const EventBatch = v.pipe(
  v.object({
    events: v.pipe(v.array(EventEnvelope), v.minLength(1), v.maxLength(LIMITS.batchEvents)),
  }),
  v.check((b) => new Set(b.events.map((e) => e.eventId)).size === b.events.length, "duplicate eventId in batch"),
  v.check((b) => utf8(JSON.stringify(b)) <= LIMITS.batchBytes, "batch too large"),
);
export type EventBatch = v.InferOutput<typeof EventBatch>;

export const EventBatchResponse = v.object({
  accepted: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
  duplicates: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
  rejected: v.pipe(v.array(v.object({ eventId: v.string(), code: Text(64) })), v.maxLength(LIMITS.batchEvents)),
});
export type EventBatchResponse = v.InferOutput<typeof EventBatchResponse>;
