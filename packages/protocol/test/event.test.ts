import * as v from "valibot";
import { describe, expect, it } from "vitest";
import { EventBatch, EventBatchResponse, EventEnvelope, LIMITS } from "../src/index.js";

let seq = 0;
const ulid = (n: number) => `01J${String(n).padStart(23, "0")}`;
function envelope(extra: Record<string, unknown> = {}): Record<string, unknown> {
  seq += 1;
  return {
    v: 1,
    eventId: ulid(seq),
    deviceSeq: seq,
    ts: "2026-11-25T10:00:00.123Z",
    sessionId: "00000000-0000-4000-8000-000000000001",
    kind: "tool_pre",
    tool: { name: "Bash", builtin: true },
    verdict: "allow",
    appliedAs: "allow",
    actionRisk: { level: "read", tags: ["exec.read"], unanalyzable: false },
    summary: { cmd: "npm test" },
    timing: { totalMs: 42, engineMs: 3 },
    versions: { plugin: "0.0.0", engine: "0.1.1", ruleset: "baseline" },
    mode: "balanced",
    degraded: false,
    project: { idHash: "a".repeat(64), label: "glassbox" },
    ...extra,
  };
}
const ok = (x: unknown) => v.safeParse(EventEnvelope, x).success;

describe("EventEnvelope", () => {
  it("accepts a valid tool event", () => {
    expect(v.safeParse(EventEnvelope, envelope()).issues).toBeUndefined();
  });

  it("requires `tool` on tool events", () => {
    const rest = envelope();
    delete rest["tool"];
    expect(ok(rest)).toBe(false);
    expect(ok({ ...rest, kind: "heartbeat" })).toBe(true);
  });

  it("accepts project-relative and ~/ summary paths", () => {
    for (const path of ["src/app.ts", "src\\auth\\token.ts", "~/…/notes.txt", "~/x/y.ts"]) {
      expect(ok(envelope({ summary: { path } })), path).toBe(true);
    }
  });

  it("checks timestamps, sequence numbers and ids", () => {
    for (const ts of ["2026-13-45T10:00:00Z", "2026-11-25 10:00:00Z", "2026-11-25T10:00:00", "yesterday"]) {
      expect(ok(envelope({ ts })), ts).toBe(false);
    }
    for (const deviceSeq of [-1, 1.5, 2 ** 53, Number.NaN]) {
      expect(ok(envelope({ deviceSeq })), String(deviceSeq)).toBe(false);
    }
  });

  it("only allows degradedReasons on degraded events", () => {
    expect(ok(envelope({ degraded: true, degradedReasons: ["ruleset-tampered"] }))).toBe(true);
    expect(ok(envelope({ degradedReasons: ["ruleset-tampered"] }))).toBe(false);
  });
});

describe("EventEnvelope: red team", () => {
  it("RT-PROTO-14: absolute paths can't leak through summary.path", () => {
    for (const path of ["C:\\Users\\bob\\secret.txt", "c:/Users/bob", "C:x", "/home/bob/.ssh/id_rsa", "\\\\server\\share\\x",
      "\\\\?\\C:\\x", "~bob/.ssh", "../outside.txt", "src/../../etc/passwd", "a\\..\\..\\b", "src/\u0000x"]) {
      expect(ok(envelope({ summary: { path } })), path).toBe(false);
    }
  });

  it("RT-PROTO-15: summary.host takes a host only, no path or query", () => {
    expect(ok(envelope({ summary: { host: "example.com" } }))).toBe(true);
    for (const host of ["example.com/a?token=x", "user:pw@example.com", "https://example.com"]) {
      expect(ok(envelope({ summary: { host } })), host).toBe(false);
    }
  });

  it("RT-PROTO-16: content limits count UTF-8 bytes, not characters", () => {
    const input = "€".repeat(30_000); // 30,000 chars, 90,000 bytes
    expect(input.length).toBeLessThan(LIMITS.contentFieldBytes);
    expect(ok(envelope({ content: { input, truncated: false } }))).toBe(false);
    expect(ok(envelope({ content: { input: "€".repeat(20_000), truncated: false } }))).toBe(true);
  });

  it("RT-PROTO-17: a whole event over the size limit is rejected even when each field is within its own", () => {
    const findings = Array.from({ length: LIMITS.findings }, (_, i) => ({
      // Multi-byte evidence: 200 characters (within the field limit), 600 bytes.
      ruleId: `CP-X-${String(i).padStart(3, "0")}`, category: "c".repeat(64), severity: "high", location: "l".repeat(256), evidence: "€".repeat(200),
    }));
    const big = envelope({ findings, summary: { cmd: "x".repeat(200), ruleIds: Array(20).fill("r".repeat(32)) } });
    expect(new TextEncoder().encode(JSON.stringify(big)).length).toBeGreaterThan(LIMITS.eventBytes);
    expect(ok(big)).toBe(false);
  });

  it("RT-PROTO-18: fields outside the schema (tenant, token) are stripped, not passed on", () => {
    const r = v.safeParse(EventEnvelope, envelope({ tenantId: "tenant-b", deviceToken: "gbx_secret" }));
    expect(r.success).toBe(true);
    expect(JSON.stringify(r.output)).not.toMatch(/tenant-b|gbx_secret/);
  });

  it("RT-PROTO-19: event ids must be ULIDs (no lower case, no I/L/O/U, no overflow)", () => {
    for (const eventId of [ulid(1).toLowerCase(), "01JIIIIIIIIIIIIIIIIIIIIIII", "01JLLLLLLLLLLLLLLLLLLLLLLL", "81J00000000000000000000000", `${ulid(1)}0`, ""]) {
      expect(ok(envelope({ eventId })), eventId).toBe(false);
    }
  });

  it("RT-PROTO-20: the project label is a name, not a path", () => {
    expect(ok(envelope({ project: { idHash: "a".repeat(64), label: "C:\\Users\\bob\\proj" } }))).toBe(false);
    expect(ok(envelope({ project: { idHash: "A".repeat(64), label: "proj" } }))).toBe(false);
  });
});

describe("EventBatch", () => {
  it("accepts a batch and strips a tenant id from the body (RT-PROTO-21)", () => {
    const r = v.safeParse(EventBatch, { tenantId: "tenant-b", events: [envelope(), envelope()] });
    expect(r.success).toBe(true);
    expect(r.output).not.toHaveProperty("tenantId");
  });

  it("RT-PROTO-22: a batch can't repeat an event id (replayed events inside one batch)", () => {
    const e = envelope();
    expect(v.safeParse(EventBatch, { events: [e, e] }).success).toBe(false);
  });

  it("enforces the event count limit", () => {
    expect(v.safeParse(EventBatch, { events: [] }).success).toBe(false);
    const many = Array.from({ length: LIMITS.batchEvents + 1 }, () => envelope({ kind: "heartbeat", tool: undefined, verdict: undefined, appliedAs: undefined, actionRisk: undefined }));
    expect(v.safeParse(EventBatch, { events: many }).success).toBe(false);
  });

  it("parses the server response", () => {
    expect(v.safeParse(EventBatchResponse, { accepted: 2, duplicates: 0, rejected: [] }).success).toBe(true);
  });
});
