// Rulesets (spec §10): signature, downgrade, Q9 protection-degraded (I17), I6 self-tests,
// I12 wording, layering rules.
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { EMBEDDED_BASELINE, checkToolCall, type LoadedRuleset } from "../../src/index.js";
import { BASELINE_TEST_CASES, loadRuleset, runRuleSelfTests } from "../../src/ruleset-entry.js";
import { jcs } from "../../src/util/jcs.js";
import { acrossModes, bash, builtin, ctx } from "../helpers.js";

const NOW = "2026-11-18T00:00:00Z";
const sk = ed25519.utils.randomSecretKey();
const pk = ed25519.getPublicKey(sk);
const TRUSTED = [{ keyId: "test-key", publicKey: pk }];

function envelope(payload: Record<string, unknown>, opts: { key?: Uint8Array; keyId?: string; tamper?: boolean } = {}) {
  const body = new TextEncoder().encode(jcs(payload));
  const msg = new Uint8Array([...new TextEncoder().encode("glassbox-ruleset-v1\0"), ...body]);
  const sig = ed25519.sign(msg, opts.key ?? sk);
  const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
  const payloadB64 = opts.tamper ? b64(new TextEncoder().encode(jcs({ ...payload, rules: [] }))) : b64(body);
  return JSON.stringify({ format: "glassbox-ruleset-envelope/v1", payload: payloadB64, signatures: [{ keyId: opts.keyId ?? "test-key", alg: "ed25519", sig: b64(sig) }] });
}

const payload = (over: Record<string, unknown> = {}) => ({
  rulesetId: "glassbox-baseline",
  channel: "baseline",
  version: "2099.1.1",
  sequence: EMBEDDED_BASELINE.sequence + 1,
  createdAt: "2026-11-01T00:00:00Z",
  expiresAt: "2027-11-01T00:00:00Z",
  minEngineVersion: "0.0.0",
  rules: EMBEDDED_BASELINE.rules,
  ...over,
});

const load = (env: string, minSequence = 0) => loadRuleset(env, { minSequence, now: NOW, trustedKeys: TRUSTED });

describe("signature and loading", () => {
  it("a validly signed newer ruleset loads", () => {
    const r = load(envelope(payload()));
    expect(r.status).toBe("ok");
    expect(r.protectionDegraded).toBe(false);
  });

  it("a tampered payload is rejected → embedded baseline, protection-degraded", () => {
    const r = load(envelope(payload(), { tamper: true }));
    expect(r.status).toBe("fallback");
    expect(r.protectionDegraded).toBe(true);
    expect(r.degradedCause).toBe("tampered");
    expect(r.rules.length).toBe(EMBEDDED_BASELINE.rules.length);
  });

  it("an untrusted key is treated as tampering", () => {
    const other = ed25519.utils.randomSecretKey();
    expect(load(envelope(payload(), { key: other })).degradedCause).toBe("tampered");
  });

  it("the embedded keys are used when trustedKeys is not passed (test key is not trusted)", () => {
    expect(loadRuleset(envelope(payload()), { minSequence: 0, now: NOW }).protectionDegraded).toBe(true);
  });

  it("a downgrade (sequence below the high-water mark) is rejected", () => {
    const r = load(envelope(payload({ sequence: 5 })), 10);
    expect(r.degradedCause).toBe("downgrade");
    expect(r.protectionDegraded).toBe(true);
  });

  it("a missing/empty cache or one too new for the engine falls back silently", () => {
    for (const r of [load(""), load(envelope(payload({ minEngineVersion: "999.0.0" })))]) {
      expect(r.status).toBe("fallback");
      expect(r.protectionDegraded).toBe(false);
    }
  });

  it("a critical rule with confidence < 0.9 fails validation", () => {
    const bad = { ...EMBEDDED_BASELINE.rules[0]!, id: "CP-TEST-999", severity: "critical", confidence: 0.5 };
    const r = load(envelope(payload({ rules: [...EMBEDDED_BASELINE.rules, bad] })));
    expect(r.status).not.toBe("ok");
  });

  it("an expired ruleset still works with an info finding (CP-INTEGRITY-004)", () => {
    const r = load(envelope(payload({ expiresAt: "2026-01-01T00:00:00Z" })));
    expect(r.status).toBe("ok");
    const d = bash("ls", ctx({ ruleset: r }));
    expect(d.findings.map((f) => f.ruleId)).toContain("CP-INTEGRITY-004");
    expect(d.verdict).toBe("allow");
  });

  it("private rulesets can only add PV- rules", () => {
    const priv = payload({ rulesetId: "acme-private", channel: "private", rules: [{ ...EMBEDDED_BASELINE.rules[0]! }] });
    expect(load(envelope(priv)).status).not.toBe("ok");
  });

  it("garbage never throws", () => {
    for (const g of ["{", "null", "[]", '{"format":"x"}', new Uint8Array([0xff, 0, 1])]) {
      expect(() => loadRuleset(g, { minSequence: 0, now: NOW })).not.toThrow();
    }
  });
});

describe("I17: protection-degraded (Q9)", () => {
  const tampered: LoadedRuleset = load(envelope(payload(), { tamper: true }));
  const c = (mode: "strict" | "balanced" | "autopilot") => ctx({ ruleset: tampered, policy: { mode } });

  it("high-risk ⇒ ≥ ask; autopilot deny", () => {
    expect(bash("curl https://example.com", c("balanced")).verdict).toBe("ask");
    expect(bash("rm x", c("balanced")).verdict).toBe("ask");
    expect(bash("rm x", c("autopilot")).verdict).toBe("deny");
  });

  it("read and write-reversible verdicts are identical to the clean baseline", () => {
    for (const cmd of ["ls", "cat a", "mkdir x", "git add .", "pnpm test", "git commit -m x"]) {
      for (const mode of ["strict", "balanced", "autopilot"] as const) {
        expect(bash(cmd, c(mode)).verdict, `${mode} ${cmd}`).toBe(bash(cmd, ctx({ policy: { mode } })).verdict);
      }
    }
  });

  it("Decisions carry protectionDegraded, CP-INTEGRITY-001 (info), a sticky signal, and are not degraded", () => {
    const d = bash("ls", c("balanced"));
    expect(d.protectionDegraded).toBe(true);
    expect(d.degraded).toBe(false);
    expect(d.findings.find((f) => f.ruleId === "CP-INTEGRITY-001")?.severity).toBe("info");
    expect(d.signals.some((s) => s.kind === "protection-degraded")).toBe(true);
  });

  it("the signal persists: a later call with a clean ruleset is still protection-degraded", () => {
    const sig = bash("ls", c("balanced")).signals.filter((s) => s.kind === "protection-degraded");
    const later = bash("curl https://example.com", ctx({ signals: sig.map((s) => ({ ...s, atCall: 1 })), limits: { signalTtlCalls: 1 } }));
    expect(later.protectionDegraded).toBe(true);
    expect(later.verdict).toBe("ask");
  });

  it("only an unavailable baseline denies non-read actions (R17)", () => {
    const unavailable = { ...EMBEDDED_BASELINE, status: "unavailable", rules: [] } as LoadedRuleset;
    const u = ctx({ ruleset: unavailable });
    expect(bash("mkdir x", u).verdict).toBe("deny");
    expect(bash("ls", u).verdict).toBe("warn");
    expect(acrossModes((cc) => builtin("Write", { file_path: "/home/u/proj/a", content: "" }, cc), u)).toEqual(["deny", "deny", "deny"]);
  });
});

describe("embedded baseline", () => {
  it("is ok and frozen", () => {
    expect(EMBEDDED_BASELINE.status).toBe("ok");
    expect(Object.isFrozen(EMBEDDED_BASELINE)).toBe(true);
    expect(Object.isFrozen(EMBEDDED_BASELINE.rules)).toBe(true);
  });

  it("I6: every declarative rule's own positive and negative cases pass (≥ 3 each)", () => {
    // The embedded baseline ships its cases in a separate module (start-up budget).
    const report = runRuleSelfTests(EMBEDDED_BASELINE, BASELINE_TEST_CASES);
    expect(report.failures).toEqual([]);
    for (const r of EMBEDDED_BASELINE.rules) {
      if (r.matcher.type === "structural") continue;
      expect(BASELINE_TEST_CASES[r.id]?.positive.length ?? 0, r.id).toBeGreaterThanOrEqual(3);
      expect(BASELINE_TEST_CASES[r.id]?.negative.length ?? 0, r.id).toBeGreaterThanOrEqual(3);
    }
  });

  it("the generated baseline files are in sync with rules/*.json", async () => {
    const { execFileSync } = await import("node:child_process");
    const { fileURLToPath } = await import("node:url");
    const script = fileURLToPath(new URL("../../../rules-baseline/scripts/build.mjs", import.meta.url));
    expect(() => execFileSync(process.execPath, [script, "--check"], { stdio: "pipe" })).not.toThrow();
  });

  it("no credential-shaped literal is committed in the rules (placeholders only)", async () => {
    const { readFileSync } = await import("node:fs");
    const { detectSecrets } = await import("../../src/secrets/detect.js");
    for (const f of ["../../src/ruleset/baseline.generated.ts", "../../src/ruleset/baseline-tests.generated.ts", "../../../rules-baseline/rules/declarative.json"]) {
      const text = readFileSync(new URL(f, import.meta.url), "utf8");
      expect(detectSecrets(text).filter((s) => !s.example && s.type !== "generic-high-entropy").map((s) => s.type), f).toEqual([]);
    }
  });

  it("I12: no rule text uses overclaiming words", () => {
    const banned = /\b(safe|secure|verified|trusted|guarantee)\b/i;
    for (const r of EMBEDDED_BASELINE.rules) {
      expect(r.explanation, r.id).not.toMatch(banned);
      expect(r.remediation, r.id).not.toMatch(banned);
    }
  });

  it("rule ids are unique and well-formed; critical ⇒ confidence ≥ 0.9", () => {
    const ids = EMBEDDED_BASELINE.rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const r of EMBEDDED_BASELINE.rules) {
      expect(r.id).toMatch(/^CP-[A-Z]+-\d{3}$/);
      if (r.severity === "critical") expect(r.confidence).toBeGreaterThanOrEqual(0.9);
    }
  });

  it("every rule id the engine can emit exists in the baseline", async () => {
    const { ENGINE_RULE_IDS } = await import("../../src/rules/ids.js");
    const have = new Set(EMBEDDED_BASELINE.rules.map((r) => r.id));
    for (const id of ENGINE_RULE_IDS) expect(have.has(id), id).toBe(true);
  });

  it("is used by default and checkToolCall reports its version", () => {
    const d = checkToolCall({ serverId: "builtin", toolName: "Bash", arguments: { command: "ls" } }, ctx());
    expect(d.rulesetVersion).toContain("glassbox-baseline@");
  });
});
