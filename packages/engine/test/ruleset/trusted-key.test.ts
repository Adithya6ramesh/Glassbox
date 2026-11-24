// The production ruleset signing key (public half) embedded in the engine, and attacks on it.
// The private key is offline with the maintainer, so no test here can produce a valid
// production signature: these tests check that nothing else is accepted.
import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { EMBEDDED_BASELINE } from "../../src/index.js";
import { EMBEDDED_TRUSTED_KEYS, REVOKED_KEY_IDS, loadRuleset } from "../../src/ruleset-entry.js";
import { jcs } from "../../src/util/jcs.js";

const NOW = "2026-11-25T00:00:00Z";
const PINNED_SHA256 = "67872a7dd309ddc3c7eb69e20a67125c77767673976bae97149ec782799f62a0";

function envelope(sk: Uint8Array, keyId: string): string {
  const payload = {
    rulesetId: "glassbox-baseline", channel: "baseline", version: "2099.1.1", sequence: EMBEDDED_BASELINE.sequence + 1,
    createdAt: "2026-11-01T00:00:00Z", expiresAt: "2027-11-01T00:00:00Z", minEngineVersion: "0.0.0", rules: EMBEDDED_BASELINE.rules,
  };
  const body = new TextEncoder().encode(jcs(payload));
  const msg = new Uint8Array([...new TextEncoder().encode("glassbox-ruleset-v1\0"), ...body]);
  const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
  return JSON.stringify({ format: "glassbox-ruleset-envelope/v1", payload: b64(body), signatures: [{ keyId, alg: "ed25519", sig: b64(ed25519.sign(msg, sk)) }] });
}

describe("embedded trusted key", () => {
  it("is exactly gbx-2026-a, a 32-byte Ed25519 key whose hash is pinned", () => {
    expect(EMBEDDED_TRUSTED_KEYS.map((k) => k.keyId)).toEqual(["gbx-2026-a"]);
    const k = EMBEDDED_TRUSTED_KEYS[0]!;
    expect(k.publicKey.length).toBe(32);
    expect(createHash("sha256").update(k.publicKey).digest("hex")).toBe(PINNED_SHA256);
    expect(() => ed25519.Point.fromBytes(k.publicKey)).not.toThrow(); // a valid curve point
  });

  it("no key is revoked yet", () => {
    expect(REVOKED_KEY_IDS).toEqual([]);
  });

  it("RT-KEY-1: a ruleset signed by another key under the name gbx-2026-a is rejected as tampered", () => {
    const r = loadRuleset(envelope(ed25519.utils.randomSecretKey(), "gbx-2026-a"), { minSequence: 0, now: NOW });
    expect(r.status).toBe("fallback");
    expect(r.degradedCause).toBe("tampered");
  });

  it("RT-KEY-2: swapping the exported key bytes doesn't make the engine trust another key", () => {
    const sk = ed25519.utils.randomSecretKey();
    const exported = EMBEDDED_TRUSTED_KEYS[0]!.publicKey as Uint8Array;
    const saved = exported.slice();
    try {
      exported.set(ed25519.getPublicKey(sk));
      const r = loadRuleset(envelope(sk, "gbx-2026-a"), { minSequence: 0, now: NOW });
      expect(r.degradedCause).toBe("tampered");
    } finally {
      exported.set(saved);
    }
  });

  it("RT-KEY-3: the key list can't be extended or replaced", () => {
    expect(Object.isFrozen(EMBEDDED_TRUSTED_KEYS)).toBe(true);
    expect(Object.isFrozen(EMBEDDED_TRUSTED_KEYS[0])).toBe(true);
    expect(() => (EMBEDDED_TRUSTED_KEYS as unknown as unknown[]).push({ keyId: "x", publicKey: new Uint8Array(32) })).toThrow();
  });

  it("RT-KEY-4: an unknown keyId is rejected even if its signature is valid", () => {
    expect(loadRuleset(envelope(ed25519.utils.randomSecretKey(), "gbx-2026-b"), { minSequence: 0, now: NOW }).degradedCause).toBe("tampered");
  });

  it("RT-KEY-5: the private key is not in the repository", () => {
    // The public key is 32 bytes; nothing PEM-shaped with PRIVATE in it may be committed. The
    // repo-wide scan for private-key blocks (including "ENCRYPTED PRIVATE KEY", the header of an
    // openssl-encrypted key file) lives in test/static/no-secrets.test.ts.
    expect(EMBEDDED_TRUSTED_KEYS.every((k) => k.publicKey.length === 32)).toBe(true);
  });
});
