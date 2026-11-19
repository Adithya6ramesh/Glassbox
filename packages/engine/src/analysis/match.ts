// Layer 1 declarative matching (engine-spec §3.2, §6.6, §10.1).
import { findDecodable } from "../canon/decode.js";
import { buildViews, type Views } from "../canon/views.js";
import { detectSecrets } from "../secrets/detect.js";
import type { Matcher, RuleDef, Severity, ViaKind, ViewName } from "../types.js";
import { findAll } from "../util/re.js";

/** A text segment with all its views (fields over the scan window are split in two). */
export interface Segment {
  offset: number;
  views: Views;
  rawNorm: string;
  decoded: { start: number; end: number; via: ViaKind; views: Views; nested: boolean }[];
  tagSpan: { start: number; end: number } | null;
}

export interface FieldScan {
  segments: Segment[];
  windowed: boolean;
  decodeExhausted: boolean;
}

const RE_WORDCH = /^[\p{L}\p{M}\p{N}]$/u;
const RE_WS = /^\p{White_Space}$/u;

function rawNormOf(s: string): string {
  // Like norm, but invisibles/ANSI/bidi/tags are NOT removed: used to tell whether a
  // match only exists because hidden characters were stripped (§6.6 invisible-stripped).
  let out = "";
  let space = false;
  for (const ch of s) {
    let t = ch;
    for (let n = 0; n < 4; n++) { const x = t.normalize("NFKC").toLowerCase(); if (x === t) break; t = x; }
    for (const c of t) {
      if (RE_WS.test(c)) { space = out.length > 0; continue; }
      if (space) { out += " "; space = false; }
      out += c;
    }
  }
  return out;
}

function tagSpan(s: string): { start: number; end: number } | null {
  let start = -1, end = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s.codePointAt(i) ?? 0;
    if (c >= 0xe0000 && c <= 0xe007f) { if (start < 0) start = i; end = i + 2; }
    if (c > 0xffff) i++;
  }
  return start < 0 ? null : { start, end };
}

function segmentOf(text: string, offset: number, budget: { bytes: number }, maxDepth: number): Segment {
  const views = buildViews(text);
  const decoded: Segment["decoded"] = [];
  const queue: { src: string; depth: number; base: { start: number; end: number } | null }[] = [{ src: text, depth: 0, base: null }];
  while (queue.length > 0 && budget.bytes > 0) {
    const q = queue.shift() as (typeof queue)[number];
    if (q.depth >= maxDepth) continue;
    for (const d of findDecodable(q.src, budget)) {
      const span = q.base ?? { start: d.start, end: d.end };
      decoded.push({ start: span.start, end: span.end, via: d.via, views: buildViews(d.text), nested: q.depth > 0 });
      queue.push({ src: d.text, depth: q.depth + 1, base: span });
      if (decoded.length > 64) break;
    }
  }
  return { offset, views, rawNorm: rawNormOf(text), decoded, tagSpan: tagSpan(text) };
}

export function scanField(text: string, maxFieldScanBytes: number, budget: { bytes: number }, maxDecodeDepth: number): FieldScan {
  const before = budget.bytes;
  if (text.length <= maxFieldScanBytes) {
    const seg = segmentOf(text, 0, budget, maxDecodeDepth);
    return { segments: [seg], windowed: false, decodeExhausted: budget.bytes <= 0 && before > 0 && seg.decoded.length > 0 };
  }
  const h = Math.floor(maxFieldScanBytes * 0.75);
  const t = maxFieldScanBytes - h;
  return {
    segments: [segmentOf(text.slice(0, h), 0, budget, maxDecodeDepth), segmentOf(text.slice(text.length - t), text.length - t, budget, maxDecodeDepth)],
    windowed: true,
    decodeExhausted: budget.bytes <= 0,
  };
}

// ── Phrase matching on word tokens ──────────────────────────────────────

interface Token { w: string; start: number; end: number }

export function tokenize(s: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < s.length) {
    const ch = String.fromCodePoint(s.codePointAt(i) ?? 0);
    if (RE_WORDCH.test(ch) || ch === "'" || ch === "’") {
      const start = i;
      let w = "";
      while (i < s.length) {
        const c = String.fromCodePoint(s.codePointAt(i) ?? 0);
        if (!(RE_WORDCH.test(c) || c === "'" || c === "’")) break;
        w += c === "’" ? "'" : c;
        i += c.length;
      }
      out.push({ w, start, end: i });
    } else i += ch.length;
  }
  return out;
}

const phraseCache = new WeakMap<object, { norm: string[][]; skel: string[][] }>();

function phraseTokens(m: Extract<Matcher, { type: "phrase" }>): { norm: string[][]; skel: string[][] } {
  let c = phraseCache.get(m);
  if (!c) {
    c = {
      norm: m.phrases.map((p) => tokenize(buildViews(p).norm.text).map((t) => t.w)),
      skel: m.phrases.map((p) => tokenize(buildViews(p).skeleton.text).map((t) => t.w)),
    };
    phraseCache.set(m, c);
  }
  return c;
}

interface Hit { start: number; end: number }

function matchPhrases(text: string, phrases: string[][], gap: number): Hit | null {
  const toks = tokenize(text);
  for (let i = 0; i < toks.length; i++) {
    for (const ph of phrases) {
      if (ph.length === 0 || toks[i]?.w !== ph[0]) continue;
      let j = i, k = 1;
      while (k < ph.length) {
        let found = -1;
        for (let g = 1; g <= gap + 1 && j + g < toks.length; g++) {
          if (toks[j + g]?.w === ph[k]) { found = j + g; break; }
        }
        if (found < 0) break;
        j = found;
        k++;
      }
      if (k === ph.length) return { start: toks[i]?.start ?? 0, end: toks[j]?.end ?? 0 };
    }
  }
  return null;
}

function evalMatcher(m: Matcher, text: string, viewKind: "norm" | "skeleton" | "other", keyName?: string): Hit | null {
  switch (m.type) {
    case "phrase": {
      const pt = phraseTokens(m);
      return matchPhrases(text, viewKind === "skeleton" ? pt.skel : pt.norm, m.maxGapWords ?? 0);
    }
    case "regex": {
      const r = findAll(m.pattern, text, m.flags, 1)[0];
      return r ? { start: r.start, end: r.end } : null;
    }
    case "secret": {
      const s = detectSecrets(text, keyName).find((x) => m.detector === "any" || x.type === m.detector);
      return s ? { start: s.start, end: s.end } : null;
    }
    case "codepoints": {
      let count = 0;
      let first: Hit | null = null;
      for (let i = 0; i < text.length; i++) {
        const c = text.codePointAt(i) ?? 0;
        if (m.ranges.some(([a, b]) => c >= a && c <= b)) { count++; first ??= { start: i, end: i + 1 }; }
        if (c > 0xffff) i++;
      }
      return count >= m.minCount ? first : null;
    }
    case "all": {
      let span: Hit | null = null;
      for (const sub of m.of) {
        const h = evalMatcher(sub, text, viewKind, keyName);
        if (!h) return null;
        span = span ? { start: Math.min(span.start, h.start), end: Math.max(span.end, h.end) } : h;
      }
      return span;
    }
    case "any": {
      for (const sub of m.of) { const h = evalMatcher(sub, text, viewKind, keyName); if (h) return h; }
      return null;
    }
    case "not":
      return evalMatcher(m.of, text, viewKind, keyName) ? null : { start: 0, end: 0 };
    case "structural":
      return null;
  }
}

export interface RuleMatch {
  start: number; // original UTF-16 offset (field-relative)
  end: number;
  via: ViaKind[];
  severity: Severity;
}

const SEV: Severity[] = ["info", "low", "medium", "high", "critical"];
const maxSev = (a: Severity, b: Severity): Severity => (SEV.indexOf(a) >= SEV.indexOf(b) ? a : b);

/** Run one declarative rule on a scanned field. Returns the first match with escalation applied. */
export function matchRule(rule: RuleDef, scan: FieldScan, keyName: string | undefined): RuleMatch | null {
  const views = new Set<ViewName>(rule.views);
  const escalate = rule.escalation !== false;
  for (const seg of scan.segments) {
    const v = seg.views;
    const at = (h: Hit, map: (i: number) => number): { start: number; end: number } => ({
      start: seg.offset + map(h.start),
      end: seg.offset + map(Math.max(h.start, h.end - 1)) + 1,
    });
    // Plain views first.
    if (views.has("original")) {
      const h = evalMatcher(rule.matcher, v.original, "other", keyName);
      if (h) return { ...at(h, (i) => i), via: [], severity: rule.severity };
    }
    if (views.has("visible")) {
      const h = evalMatcher(rule.matcher, v.visible.text, "other", keyName);
      if (h) {
        const plain = evalMatcher(rule.matcher, v.original, "other", keyName);
        const via: ViaKind[] = plain ? [] : ["invisible-stripped"];
        return { ...at(h, (i) => v.visible.toOriginal(i)), via, severity: via.length && escalate ? maxSev(rule.severity, "high") : rule.severity };
      }
    }
    if (views.has("norm")) {
      const h = evalMatcher(rule.matcher, v.norm.text, "norm", keyName);
      if (h) {
        const plain = evalMatcher(rule.matcher, seg.rawNorm, "norm", keyName);
        const via: ViaKind[] = plain ? [] : ["invisible-stripped"];
        return { ...at(h, (i) => v.norm.toOriginal(i)), via, severity: via.length && escalate ? maxSev(rule.severity, "high") : rule.severity };
      }
    }
    if (views.has("skeleton")) {
      const h = evalMatcher(rule.matcher, v.skeleton.text, "skeleton", keyName);
      if (h) return { ...at(h, (i) => v.skeleton.toOriginal(i)), via: ["skeleton"], severity: escalate ? maxSev(rule.severity, "high") : rule.severity };
    }
    if (views.has("tagDecoded") && v.tagDecoded.length > 0) {
      const tv = buildViews(v.tagDecoded);
      const h = evalMatcher(rule.matcher, tv.norm.text, "norm", keyName) ?? evalMatcher(rule.matcher, tv.visible.text, "other", keyName);
      if (h) {
        const span = seg.tagSpan ?? { start: 0, end: v.original.length };
        return { start: seg.offset + span.start, end: seg.offset + span.end, via: ["tag-chars"], severity: escalate ? maxSev(rule.severity, "critical") : rule.severity };
      }
    }
    if (views.has("decoded")) {
      for (const d of seg.decoded) {
        const dv = d.views;
        const h =
          (views.has("original") ? evalMatcher(rule.matcher, dv.original, "other", keyName) : null) ??
          (views.has("visible") ? evalMatcher(rule.matcher, dv.visible.text, "other", keyName) : null) ??
          evalMatcher(rule.matcher, dv.norm.text, "norm", keyName) ??
          (views.has("skeleton") ? evalMatcher(rule.matcher, dv.skeleton.text, "skeleton", keyName) : null);
        if (h) return { start: seg.offset + d.start, end: seg.offset + d.end, via: [d.via], severity: escalate ? maxSev(rule.severity, "high") : rule.severity };
      }
    }
  }
  return null;
}

export { tagSpan };
