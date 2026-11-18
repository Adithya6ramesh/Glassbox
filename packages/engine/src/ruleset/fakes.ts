// Fake credentials for rule self-tests. Built from pieces so no credential-shaped literal
// appears in the source or the git history (public repo; secret scanners, push protection).
// Rule test cases refer to them as {{fake:<type>}}; they're expanded only when tests run.
const FAKES: Readonly<Record<string, string>> = {
  "github-token": "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0" + "k1L2m3N4o5P6q7R8",
  "aws-access-key-id": "AK" + "IA" + "Q3ZRT7Y2" + "X4WPLM5N",
  "stripe-key": "sk" + "_live_" + "Gx8Fq2Lm7Rt4Vw1Yb3Cd" + "5Hj9Kp",
  "slack-token": "xo" + "xb-" + "123456789012-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx",
  "private-key": "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\n-----END RSA " + "PRIVATE KEY-----",
};

/** Replace every {{fake:<type>}} placeholder inside strings of `v` (deep, iterative). */
export function expandFakes(v: unknown): unknown {
  const fix = (s: string) => s.replace(/\{\{fake:([a-z0-9-]+)\}\}/g, (m, t: string) => FAKES[t] ?? m);
  if (typeof v === "string") return fix(v);
  if (Array.isArray(v)) return v.map(expandFakes);
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v)) out[k] = expandFakes((v as Record<string, unknown>)[k]);
    return out;
  }
  return v;
}
