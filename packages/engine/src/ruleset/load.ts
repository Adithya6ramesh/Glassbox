// Ruleset loading.
import { ed25519 } from "@noble/curves/ed25519.js";
import * as v from "valibot";
import { decodeBase64 } from "../canon/decode.js";
import { parseJsonStrict } from "../intake/json.js";
import type { LoadedRuleset, LoadRulesetOptions, RuleDef, TrustedKey } from "../types.js";
import { isValidPattern } from "../util/re.js";
import { utf8 } from "../util/hash.js";
import { deepFreeze } from "../util/misc.js";
import { ENGINE_VERSION } from "../version.js";
import { EMBEDDED_BASELINE } from "./baseline.js";
import { EnvelopeSchema, PayloadSchema, type RulesetPayload } from "./schema.js";
import { runRuleSelfTests } from "./selftest.js";

/**
 * Trusted signing keys embedded in the engine build. Empty until the first production
 * key is created at release time: until then every signed cache is rejected and the
 * embedded baseline is used (the fail-safe direction).
 */
export const EMBEDDED_TRUSTED_KEYS: readonly TrustedKey[] = Object.freeze([]);
export const REVOKED_KEY_IDS: readonly string[] = Object.freeze([]);

const DOMAIN = utf8("glassbox-ruleset-v1\u0000");
const MAX_RULESET_BYTES = 4 * 1024 * 1024;
const BANNED_WORDS = /\b(safe|secure|verified|trusted|guarantee)\b/i;

function semverLE(a: string, b: string): boolean {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x !== y) return x < y;
  }
  return true;
}

function fallback(cause: "tampered" | "downgrade" | null, errors: string[]): LoadedRuleset {
  return deepFreeze({
    ...EMBEDDED_BASELINE,
    status: "fallback" as const,
    protectionDegraded: cause !== null,
    ...(cause !== null ? { degradedCause: cause } : {}),
    errors,
  });
}

/** Validation beyond the schema: namespaces, confidence, regexes, wording. */
export function validateRules(payload: RulesetPayload): string[] {
  const errors: string[] = [];
  const prefix = payload.channel === "baseline" ? "CP-" : "PV-";
  const ids = new Set<string>();
  for (const r of payload.rules) {
    if (!r.id.startsWith(prefix)) errors.push(`${r.id}: wrong namespace for ${payload.channel}`);
    if (ids.has(r.id)) errors.push(`${r.id}: duplicate id`);
    ids.add(r.id);
    if (r.severity === "critical" && r.confidence < 0.9) errors.push(`${r.id}: critical needs confidence ≥ 0.9`);
    if (payload.channel === "baseline" && (BANNED_WORDS.test(r.explanation) || BANNED_WORDS.test(r.remediation))) errors.push(`${r.id}: overclaiming wording`);
    const stack = [r.matcher];
    while (stack.length > 0) {
      const m = stack.pop();
      if (!m) continue;
      if (m.type === "regex" && !isValidPattern(m.flags === "i" ? `(?i)${m.pattern}` : m.pattern)) errors.push(`${r.id}: regex doesn't compile in the linear engine`);
      if (m.type === "regex" && m.anchors) {
        for (const a of m.anchors) {
          if (a !== a.toLowerCase()) errors.push(`${r.id}: anchor ${JSON.stringify(a)} isn't lowercase`);
          if ([...a].some((ch) => ch === "\u03a3" || ch === "\u03c3" || ch === "\u03c2")) errors.push(`${r.id}: anchor ${JSON.stringify(a)} contains a Greek sigma (context-dependent lowercase)`);
          if (m.flags === "i" && [...a].some((ch) => ch < " " || ch > "~")) errors.push(`${r.id}: non-ASCII anchor ${JSON.stringify(a)} on a case-insensitive regex`);
        }
      }
      if (m.type === "phrase" && m.phrases.length === 0) errors.push(`${r.id}: empty phrase list`);
      if (m.type === "all" || m.type === "any") stack.push(...m.of);
      if (m.type === "not") stack.push(m.of);
    }
  }
  return errors;
}

export function buildLoaded(payload: RulesetPayload, now: string, extra: Partial<LoadedRuleset> = {}): LoadedRuleset {
  const nowMs = Date.parse(now);
  const expMs = Date.parse(payload.expiresAt);
  return deepFreeze({
    status: "ok",
    rulesetId: payload.rulesetId,
    version: payload.version,
    sequence: payload.sequence,
    expiresAt: payload.expiresAt,
    expired: Number.isFinite(nowMs) && Number.isFinite(expMs) && nowMs > expMs,
    protectionDegraded: false,
    rules: payload.rules as unknown as readonly RuleDef[],
    irreversibleTags: payload.irreversibleTags ?? EMBEDDED_BASELINE.irreversibleTags,
    errors: [],
    ...extra,
  });
}

export function loadRuleset(envelope: Uint8Array | string, opts: LoadRulesetOptions): LoadedRuleset {
  try {
    const keys = opts?.trustedKeys ?? EMBEDDED_TRUSTED_KEYS;
    const minSequence = typeof opts?.minSequence === "number" ? opts.minSequence : 0;
    const now = typeof opts?.now === "string" ? opts.now : "";
    const size = typeof envelope === "string" ? envelope.length : envelope instanceof Uint8Array ? envelope.length : -1;
    if (size === 0) return fallback(null, ["no ruleset cache"]);
    if (size < 0) return fallback("tampered", ["envelope is not a string or bytes"]);
    if (size > MAX_RULESET_BYTES) return fallback("tampered", ["envelope too large"]);

    // 1–3: envelope shape and signature.
    const env = parseJsonStrict(envelope, { maxDepth: 8, maxNodes: 1000 });
    const envOk = env.ok ? v.safeParse(EnvelopeSchema, env.value) : null;
    if (!envOk?.success) return fallback("tampered", ["malformed envelope"]);
    const payloadBytes = decodeBase64(envOk.output.payload);
    if (!payloadBytes) return fallback("tampered", ["payload is not base64"]);
    const message = new Uint8Array(DOMAIN.length + payloadBytes.length);
    message.set(DOMAIN);
    message.set(payloadBytes, DOMAIN.length);
    const signed = envOk.output.signatures.some((s) => {
      if (REVOKED_KEY_IDS.includes(s.keyId)) return false;
      const key = keys.find((k) => k.keyId === s.keyId);
      const sig = decodeBase64(s.sig);
      if (!key || !sig || sig.length !== 64) return false;
      try {
        return ed25519.verify(sig, message, key.publicKey);
      } catch {
        return false;
      }
    });
    if (!signed) return fallback("tampered", ["signature check failed"]);

    // 4–5: payload parse and validation. A validly signed but invalid payload is our own
    // mistake, not tampering: fall back without protection-degraded.
    const parsed = parseJsonStrict(payloadBytes, { maxDepth: 32, maxNodes: 2_000_000 });
    if (!parsed.ok || parsed.issues.some((i) => i.code === "CP-PARSE-001")) return fallback(null, ["payload is not valid strict JSON"]);
    const pv = v.safeParse(PayloadSchema, parsed.value);
    if (!pv.success) return fallback(null, ["payload schema: " + (pv.issues[0]?.message ?? "invalid")]);
    const payload = pv.output;
    const errors = validateRules(payload);
    if (errors.length > 0) return fallback(null, errors);

    // 6: downgrade. 7: engine version.
    if (payload.channel === "baseline" && payload.sequence < Math.max(minSequence, EMBEDDED_BASELINE.sequence)) {
      return fallback("downgrade", [`sequence ${payload.sequence} is below the high-water mark`]);
    }
    if (!semverLE(payload.minEngineVersion, ENGINE_VERSION)) return fallback(null, ["ruleset needs a newer engine"]);

    // 8: self-test. Rules that fail their own cases are dropped.
    const candidate = buildLoaded(payload, now);
    const report = runRuleSelfTests(candidate);
    if (report.failures.length > 0) {
      const bad = new Set(report.failures.map((f) => f.ruleId));
      return buildLoaded({ ...payload, rules: payload.rules.filter((r) => !bad.has(r.id)) }, now, {
        status: "loaded-with-errors",
        errors: report.failures.map((f) => `${f.ruleId}: ${f.reason}`),
      });
    }
    return candidate;
  } catch {
    return fallback("tampered", ["unexpected error while loading"]);
  }
}
