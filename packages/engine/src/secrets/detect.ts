// Secret detectors (engine-spec §8.1). Patterns run on the linear regex engine (re2js).
import { findAll } from "../util/re.js";

export interface SecretHit {
  type: string;
  start: number;
  end: number;
  value: string;
  confidence: number;
  example: boolean;
}

interface Detector {
  type: string;
  /**
   * Literals every match contains. When none occurs in the text the pattern can't match, so
   * the regex pass is skipped (a plain substring search is far cheaper than re2js's NFA).
   * Keep these in sync with `pattern`: the static test in secrets.test checks each pattern's
   * example matches contain one of its anchors.
   */
  anchors: readonly string[];
  anchorsCI?: boolean;
  pattern: string;
  flags?: "i";
  group?: number;
  confidence: number;
  validate?: (value: string, full: string) => number | null; // returns confidence override or null to reject
}

const PLACEHOLDER = /^(\*+|x+|password|passwd|secret|changeme|<[^>]*>|\$\{[^}]*\}|\$[A-Z_]+|%[A-Z_]+%|\{\{[^}]*\}\})$/i;

function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  const n = [...s].length;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function classes(s: string): number {
  let lower = 0, upper = 0, digit = 0, other = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 97 && c <= 122) lower = 1;
    else if (c >= 65 && c <= 90) upper = 1;
    else if (c >= 48 && c <= 57) digit = 1;
    else other = 1;
  }
  return lower + upper + digit + other;
}

const DETECTORS: Detector[] = [
  { type: "private-key", anchors: ["PRIVATE KEY"], pattern: "-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----", confidence: 0.99 },
  { type: "anthropic-key", anchors: ["sk-ant-"], pattern: "sk-ant-(?:api|admin)\\d\\d-[A-Za-z0-9_\\-]{80,}", confidence: 0.98 },
  { type: "github-token", anchors: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"], pattern: "(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})", confidence: 0.95 },
  { type: "gitlab-token", anchors: ["glpat-", "gldt-", "glrt-"], pattern: "gl(?:pat|dt|rt)-[A-Za-z0-9_\\-]{20,}", confidence: 0.95 },
  { type: "slack-webhook", anchors: ["https://hooks.slack.com/services/"], pattern: "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", confidence: 0.95 },
  { type: "slack-token", anchors: ["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-", "xapp-"], pattern: "(?:xox[abprs]|xapp)-[A-Za-z0-9\\-]{10,}", confidence: 0.95 },
  { type: "stripe-key", anchors: ["sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_"], pattern: "(?:(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}|whsec_[A-Za-z0-9]{24,})", confidence: 0.95 },
  { type: "gcp-api-key", anchors: ["AIza"], pattern: "AIza[0-9A-Za-z_\\-]{35}", confidence: 0.95 },
  { type: "aws-access-key-id", anchors: ["AKIA", "ASIA", "ABIA", "ACCA"], pattern: "(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}", confidence: 0.95 },
  {
    type: "aws-secret-access-key", anchors: ["aws"], anchorsCI: true,
    pattern: "(?i)aws[A-Za-z0-9_\\-]{0,20}(?:secret|key)[A-Za-z0-9_\\-]{0,20}[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9/+]{40})",
    group: 1, confidence: 0.8,
    validate: (v) => (entropy(v) >= 4.0 ? null : -1),
  },
  { type: "azure-storage-key", anchors: ["AccountKey="], pattern: "AccountKey=[A-Za-z0-9+/=]{20,}", confidence: 0.9 },
  { type: "azure-conn-string", anchors: ["SharedAccessSignature="], pattern: "SharedAccessSignature=[^;\\s\"']{16,}", confidence: 0.9 },
  {
    type: "openai-key", anchors: ["sk-"], pattern: "sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\\-]{20,}", confidence: 0.85,
    validate: (v) => (v.startsWith("sk-ant-") ? -1 : null),
  },
  {
    type: "jwt", anchors: ["eyJ"], pattern: "eyJ[A-Za-z0-9_\\-]{5,}\\.eyJ[A-Za-z0-9_\\-]{5,}\\.[A-Za-z0-9_\\-]{10,}", confidence: 0.85,
    validate: (v) => {
      try {
        const head = (v.split(".")[0] ?? "").replace(/-/g, "+").replace(/_/g, "/");
        const json = atob(head + "=".repeat((4 - (head.length % 4)) % 4));
        return json.includes('"alg"') ? null : -1;
      } catch {
        return -1;
      }
    },
  },
  {
    type: "db-connection-string", anchors: ["postgres://", "postgresql://", "mysql://", "mongodb://", "mongodb+srv://", "redis://", "rediss://", "amqp://", "amqps://", "mssql://"],
    pattern: "(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|rediss|amqps?|mssql)://([^:@/\\s\"']+):([^@\\s\"']+)@[^\\s/\"']+",
    confidence: 0.9,
    validate: (v) => {
      const m = /:\/\/[^:@/\s]+:([^@\s]+)@/.exec(v.slice(0, 512));
      const pw = m?.[1] ?? "";
      return pw.length === 0 || PLACEHOLDER.test(pw) ? -1 : null;
    },
  },
];

const GENERIC_ANCHORS = ["key", "token", "secret", "passw", "pwd", "auth", "credential", "bearer", "session", "private"];

const KEYWORD = "(?i)[A-Za-z0-9_.\\-]*(?:key|token|secret|passw(?:or)?d|pwd|auth|credential|bearer|session|private)[A-Za-z0-9_.\\-]*";
const KEY_NAME = /(key|token|secret|passw(or)?d|pwd|auth|credential|api[-_]?key|private|bearer|session)/i;
const EXCLUDED_KEY = /(^|[^a-z])(sha|commit|hash|checksum|integrity|digest|etag|id)$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEXONLY = /^[0-9a-f]+$/i;

function looksGeneric(v: string): boolean {
  if (v.length < 20 || v.length > 512) return false;
  if (UUID.test(v) || PLACEHOLDER.test(v)) return false;
  if (HEXONLY.test(v) && (v.length === 40 || v.length === 64 || v.length === 32)) return false;
  if (v.includes(" ") || v.includes("/") && v.split("/").length > 3) return false;
  return entropy(v) >= 3.5 && classes(v) >= 2;
}

function isExample(v: string): boolean {
  return /EXAMPLE|example|xxxxxxxx|XXXXXXXX|0000000000|1234567890abcdef/.test(v.slice(0, 512)) || v === "AKIAIOSFODNN7EXAMPLE";
}

/** Private keys: extend the hit to the matching END line when present. */
function extendPem(text: string, start: number, end: number): number {
  const endMarker = text.indexOf("-----END", end);
  if (endMarker < 0 || endMarker - end > 64 * 1024) return Math.min(text.length, end + 4096);
  const close = text.indexOf("-----", endMarker + 8);
  return close < 0 ? text.length : close + 5;
}

/**
 * Detects secrets in `text`. `keyName` is the JSON key the text sits under (for the
 * generic high-entropy detector, which needs a key-like name).
 */
export function detectSecrets(text: string, keyName?: string, memo?: SecretMemo): SecretHit[] {
  if (!memo) return detectUncached(text, keyName);
  const k = keyName ?? "\u0000";
  let byText = memo.get(k);
  if (!byText) { byText = new Map(); memo.set(k, byText); }
  let hits = byText.get(text);
  if (!hits) { hits = detectUncached(text, keyName); byText.set(text, hits); }
  return hits;
}

/** Per-call cache: keyName → text → hits. Owned by one scan, never shared across calls. */
export type SecretMemo = Map<string, Map<string, SecretHit[]>>;

function detectUncached(text: string, keyName?: string): SecretHit[] {
  const hits: SecretHit[] = [];
  if (text.length < 8) return hits;
  let lower: string | undefined;
  const has = (lits: readonly string[], ci: boolean | undefined): boolean => {
    // re2 (?i) folds U+017F (long s) to s and U+212A (Kelvin) to k; toLowerCase handles the
    // Kelvin sign but not long s, so fold it here or "\u017fecret=..." would skip the pass.
    if (ci) lower ??= text.toLowerCase().replaceAll("\u017f", "s");
    const hay = ci ? (lower as string) : text;
    return lits.some((l) => hay.includes(l));
  };
  for (const d of DETECTORS) {
    if (!has(d.anchors, d.anchorsCI)) continue;
    for (const m of findAll(d.pattern, text, d.flags, 50)) {
      let start = m.start, end = m.end;
      let value = m.text;
      if (d.group !== undefined) {
        const g = m.groups[d.group - 1];
        if (!g) continue;
        const off = m.text.lastIndexOf(g);
        start = m.start + off;
        end = start + g.length;
        value = g;
      }
      if (d.type === "private-key") { end = extendPem(text, start, end); value = text.slice(start, end); }
      let confidence = d.confidence;
      if (d.validate) {
        const r = d.validate(value, text);
        if (r !== null && r < 0) continue;
        if (r !== null) confidence = r;
      }
      const example = isExample(value);
      hits.push({ type: d.type, start, end, value, confidence: example ? 0.3 : confidence, example });
    }
  }
  // Generic: key=value pairs inside text with a key-like name.
  const generic = (text.includes("=") || text.includes(":")) && has(GENERIC_ANCHORS, true);
  for (const m of generic ? findAll(`(${KEYWORD})\\s*["']?\\s*[:=]\\s*["']?([^\\s"'&,;]{20,512})`, text, undefined, 50) : []) {
    const v = m.groups[1] ?? "";
    const name = m.groups[0] ?? "";
    if (EXCLUDED_KEY.test(name) || !looksGeneric(v)) continue;
    const start = m.start + m.text.lastIndexOf(v);
    hits.push({ type: "generic-high-entropy", start, end: start + v.length, value: v, confidence: 0.6, example: isExample(v) });
  }
  // Generic: the whole field under a key-like JSON key.
  if (keyName !== undefined && KEY_NAME.test(keyName) && !EXCLUDED_KEY.test(keyName)) {
    const v = text.trim();
    if (looksGeneric(v)) {
      const start = text.indexOf(v);
      hits.push({ type: "generic-high-entropy", start, end: start + v.length, value: v, confidence: 0.6, example: isExample(v) });
    }
  }
  return resolveOverlaps(hits);
}

/** Keep the most specific hit when hits overlap (generic loses; longer wins on ties). */
function resolveOverlaps(hits: SecretHit[]): SecretHit[] {
  const rank = (h: SecretHit) => (h.type === "generic-high-entropy" ? 0 : h.type === "openai-key" ? 1 : 2);
  hits.sort((a, b) => rank(b) - rank(a) || (b.end - b.start) - (a.end - a.start) || a.start - b.start);
  const kept: SecretHit[] = [];
  for (const h of hits) {
    if (kept.some((k) => h.start < k.end && k.start < h.end)) continue;
    kept.push(h);
  }
  return kept.sort((a, b) => a.start - b.start);
}

// ── Masking (§8.2) ───────────────────────────────────────────────────────

const PUBLIC_PREFIXES = [
  "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "gldt-", "glrt-", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xapp-",
  "sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_", "sk-proj-", "sk-svcacct-", "sk-admin-", "AKIA", "ASIA", "ABIA", "ACCA", "AIza", "eyJ",
];

export function mask(type: string, value: string): string {
  if (type === "private-key") {
    const lines = value.split("\n").length;
    return `private-key:[REDACTED PEM, ${lines} lines]`;
  }
  if (type === "db-connection-string") {
    const at = value.indexOf("@");
    const scheme = value.indexOf("://");
    const colon = value.indexOf(":", scheme + 3);
    if (scheme > 0 && colon > 0 && at > colon) return value.slice(0, colon + 1) + "****" + value.slice(at);
    return "db-connection-string:****";
  }
  let prefix = "";
  const ant = /^sk-ant-(api|admin)\d\d-/.exec(value.slice(0, 20));
  if (ant) prefix = ant[0];
  else for (const p of PUBLIC_PREFIXES) if (value.startsWith(p)) { prefix = p; break; }
  const tail = value.length >= 24 ? value.slice(-4) : "";
  return `${type}:${prefix}****…${tail}`;
}
