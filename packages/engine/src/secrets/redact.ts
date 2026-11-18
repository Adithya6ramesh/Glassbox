// redact() (engine-spec §8.2): deep copy with every detected secret masked.
// Unscanned content is replaced, never passed through raw.
import { findDecodable } from "../canon/decode.js";
import { resolveLimits } from "../limits.js";
import { snapshot } from "../intake/snapshot.js";
import type { Limits, Redacted } from "../types.js";
import { isRecord, ptrSeg } from "../util/misc.js";
import { detectSecrets, mask, type SecretHit } from "./detect.js";

export interface StringRedaction { text: string; hits: SecretHit[]; masked: { type: string; masked: string }[]; truncated: boolean }

/** Redact one string. `minConfidence` lets strict-mode result rewriting mask only high-confidence hits. */
export function redactString(text: string, keyName: string | undefined, limits: Limits, minConfidence = 0): StringRedaction {
  let truncated = false;
  let head = text;
  let tail = "";
  let skipped = 0;
  if (text.length > limits.maxFieldScanBytes) {
    const h = Math.floor(limits.maxFieldScanBytes * 0.75);
    const t = limits.maxFieldScanBytes - h;
    head = text.slice(0, h);
    tail = text.slice(text.length - t);
    skipped = text.length - h - t;
    truncated = true;
  }
  const doPart = (part: string) => {
    const hits: (SecretHit & { wrapped?: boolean })[] = detectSecrets(part, keyName).filter((x) => x.confidence >= minConfidence);
    // Secrets wrapped in base64/hex/url encoding: mask the whole blob.
    for (const d of findDecodable(part, { bytes: limits.maxDecodedBytes })) {
      if (hits.some((x) => x.start < d.end && d.start < x.end)) continue;
      const inner = detectSecrets(d.text).filter((x) => x.confidence >= minConfidence);
      const first = inner[0];
      if (first) hits.push({ ...first, start: d.start, end: d.end, value: part.slice(d.start, d.end), wrapped: true });
    }
    hits.sort((a, b) => a.start - b.start);
    let out = "";
    let pos = 0;
    const masked: { type: string; masked: string }[] = [];
    for (const x of hits) {
      if (x.start < pos) continue;
      const m = x.wrapped ? `${x.type}:[REDACTED encoded]` : mask(x.type, x.value);
      out += part.slice(pos, x.start) + m;
      masked.push({ type: x.type, masked: m });
      pos = x.end;
    }
    out += part.slice(pos);
    return { out, hits, masked };
  };
  const a = doPart(head);
  if (!truncated) return { text: a.out, hits: a.hits, masked: a.masked, truncated };
  const b = doPart(tail);
  return {
    text: `${a.out}[UNSCANNED ${skipped} bytes]${b.out}`,
    hits: [...a.hits, ...b.hits],
    masked: [...a.masked, ...b.masked],
    truncated,
  };
}

function setKey(o: Record<string, unknown>, k: string, v: unknown) {
  Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
}

/** Deep redaction over a snapshot value. */
export function redactValue(value: unknown, limits: Limits, minConfidence = 0): Redacted {
  const redactions: { pointer: string; type: string; masked: string }[] = [];
  let truncated = false;
  let budget = limits.maxInputBytes * 4;
  interface Job { v: unknown; set: (x: unknown) => void; pointer: string; key: string | undefined }
  let root: unknown = null;
  const jobs: Job[] = [{ v: value, set: (x) => { root = x; }, pointer: "", key: undefined }];
  while (jobs.length > 0) {
    const j = jobs.pop() as Job;
    const v = j.v;
    if (typeof v === "string") {
      if (budget <= 0) { j.set(`[UNSCANNED ${v.length} bytes]`); truncated = true; continue; }
      budget -= v.length;
      const r = redactString(v, j.key, limits, minConfidence);
      if (r.truncated) truncated = true;
      for (const m of r.masked) redactions.push({ pointer: j.pointer, type: m.type, masked: m.masked });
      j.set(r.text);
    } else if (Array.isArray(v)) {
      const out: unknown[] = new Array<unknown>(v.length).fill(null);
      j.set(out);
      v.forEach((x: unknown, i: number) => jobs.push({ v: x, set: (y) => { out[i] = y; }, pointer: `${j.pointer}/${i}`, key: j.key }));
    } else if (isRecord(v)) {
      const out: Record<string, unknown> = {};
      j.set(out);
      for (const k of Object.keys(v)) {
        setKey(out, k, null);
        jobs.push({ v: v[k], set: (y) => setKey(out, k, y), pointer: `${j.pointer}/${ptrSeg(k)}`, key: k });
      }
    } else {
      j.set(v);
    }
  }
  return { value: root, redactions, truncated };
}

export function redact(value: unknown, opts?: { limits?: Partial<Limits> }): Redacted {
  try {
    const limits = resolveLimits(opts?.limits);
    const snap = snapshot(value, { maxDepth: limits.maxDepth, maxNodes: limits.maxNodes });
    const r = redactValue(snap.value, limits);
    return { ...r, truncated: r.truncated || snap.degraded };
  } catch {
    return { value: "[UNSCANNED]", redactions: [], truncated: true };
  }
}
