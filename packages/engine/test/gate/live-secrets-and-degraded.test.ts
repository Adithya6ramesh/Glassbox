// Spec rev 6: Q2 (live secrets in arguments to non-read tools ask) and Q4 (a broken
// context marks the session protection-degraded so the next high-risk call asks).
import { describe, expect, it } from "vitest";
import { checkToolCall, checkToolResult, type SessionSignal } from "../../src/index.js";
import { acrossModes, bash, call, ctx, FAKE, ruleIds, withSignals } from "../helpers.js";

const note = (body: string) => call({ serverId: "notes", toolName: "create_note", arguments: { title: "t", body } });
const STRIPE_TEST = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc" + "Zq";

describe("Q2: live secrets in arguments to non-read tools → ask (deny in autopilot)", () => {
  it.each([
    ["private key", FAKE.pem],
    ["Stripe live key", FAKE.stripe],
    ["database URL with a password", FAKE.pg],
    ["GitHub token", FAKE.github],
    ["AWS access key id", FAKE.aws],
  ])("%s → CP-EXFIL-032, ask", (_n, secret) => {
    const d = note(`here: ${secret}`);
    expect(ruleIds(d)).toContain("CP-EXFIL-032");
    expect(d.verdict).toBe("ask");
  });

  it("deny in autopilot, ask in strict", () => {
    expect(acrossModes((c) => checkToolCall({ serverId: "notes", toolName: "create_note", arguments: { body: FAKE.pem } }, c))).toEqual(["ask", "ask", "deny"]);
  });

  it("test-mode Stripe keys stay below ask", () => {
    const d = note(`use ${STRIPE_TEST} in staging`);
    expect(ruleIds(d)).not.toContain("CP-EXFIL-032");
    expect(["allow", "warn"]).toContain(d.verdict);
  });

  it("example and placeholder values stay below ask", () => {
    for (const body of ["AWS key: AKIAIOSFODNN7EXAMPLE", "postgresql://user:password@host:5432/db", "token=<your token here>"]) {
      expect(ruleIds(note(body)), body).not.toContain("CP-EXFIL-032");
    }
  });

  it("read-only tools are not affected", () => {
    const d = call({ serverId: "notes", toolName: "search_notes", arguments: { query: FAKE.github } });
    expect(ruleIds(d)).not.toContain("CP-EXFIL-032");
  });
});

describe("Q4: a broken context marks the session degraded", () => {
  const fetchCall = { serverId: "web", toolName: "fetch_page", arguments: { url: "https://x.example" } };
  const broken = (): Record<string, unknown> => { const b: Record<string, unknown> = { ...ctx() }; delete b.ruleset; return b; };

  it("the result itself stays warn (no ask) and emits a protection-degraded signal", () => {
    const d = checkToolResult({ call: fetchCall, result: { content: [{ type: "text", text: "hello" }] } }, broken() as never);
    expect(d.verdict).toBe("warn");
    expect(d.protectionDegraded).toBe(true);
    expect(d.signals).toContainEqual({ kind: "protection-degraded", reason: "internal-error", atCall: 0 });
  });

  it("the next high-risk call asks; a read-only call is unaffected", () => {
    const d = checkToolResult({ call: fetchCall, result: { content: [{ type: "text", text: "hello" }] } }, broken() as never);
    const next = withSignals(d.signals as SessionSignal[]);
    expect(bash("git push origin feature/x", next).verdict).toBe("ask");
    expect(bash("ls -la", next).verdict).toBe("allow");
  });

  it("in autopilot that ask becomes deny", () => {
    const d = checkToolResult({ call: fetchCall, result: { content: [{ type: "text", text: "hello" }] } }, broken() as never);
    const next = withSignals(d.signals as SessionSignal[], ctx({ policy: { mode: "autopilot" } }));
    expect(bash("git push origin feature/x", next).verdict).toBe("deny");
  });

  it("the reason is carried forward on later decisions", () => {
    const d = checkToolResult({ call: fetchCall, result: { content: [{ type: "text", text: "hello" }] } }, broken() as never);
    const later = bash("git push origin feature/x", withSignals(d.signals as SessionSignal[]));
    expect(later.signals).toContainEqual(expect.objectContaining({ kind: "protection-degraded", reason: "internal-error" }));
  });
});
