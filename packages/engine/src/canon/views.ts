// C4: Unicode views with offset maps back to the original string.
// All transforms are per code point (after invisible/ANSI removal), so each view is
// idempotent (P1) and every output position maps to an original position.
import { CONFUSABLES } from "./confusables.generated.js";
import { initTimed } from "../util/initclock.js";

export interface View {
  text: string;
  /** Original UTF-16 offset for a view UTF-16 offset. */
  toOriginal(i: number): number;
}

export interface Facts {
  invisibles: { cp: number; index: number }[];
  bidi: { cp: number; index: number }[];
  tagCount: number;
  ansi: number;
  comments: boolean;
  /** ≥ 20 consecutive newlines or ≥ 200 whitespace code points followed by more text. */
  padding: boolean;
}

export interface Views {
  original: string;
  visible: View;
  norm: View;
  skeleton: View;
  tagDecoded: string;
  facts: Facts;
}

// Built on first use of the skeleton view, not at module load, to keep start-up fast.
let CONF: Map<number, string> | null = null;
function confusable(cp: number): string | undefined {
  if (CONF === null) {
    CONF = initTimed(() => {
      const m = new Map<number, string>();
      for (const k of Object.keys(CONFUSABLES)) m.set(parseInt(k, 36), CONFUSABLES[k] as string);
      return m;
    });
  }
  return CONF.get(cp);
}

const RE_CF = /^\p{Cf}$/u;
const RE_CC = /^\p{Cc}$/u;
const RE_PICTO = /^\p{Extended_Pictographic}$/u;
const RE_WS = /^\p{White_Space}$/u;

const BIDI = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200e, 0x200f, 0x061c]);
const MARKS = new Set([0x200e, 0x200f, 0x061c]);
const HANGUL_FILLERS = new Set([0x115f, 0x1160, 0x3164, 0xffa0]);

function isRtl(cp: number): boolean {
  return (cp >= 0x0590 && cp <= 0x08ff) || (cp >= 0xfb1d && cp <= 0xfdff) || (cp >= 0xfe70 && cp <= 0xfefc) || (cp >= 0x10800 && cp <= 0x10fff) || (cp >= 0x1e800 && cp <= 0x1efff);
}

function isPicto(cp: number): boolean {
  return RE_PICTO.test(String.fromCodePoint(cp));
}

function isEmojiModifier(cp: number): boolean {
  return cp >= 0x1f3fb && cp <= 0x1f3ff;
}

interface CP { cp: number; index: number; len: number }

function codePoints(s: string): CP[] {
  const out: CP[] = [];
  for (let i = 0; i < s.length;) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        out.push({ cp: ((c - 0xd800) << 10) + (d - 0xdc00) + 0x10000, index: i, len: 2 });
        i += 2;
        continue;
      }
    }
    out.push({ cp: c, index: i, len: 1 });
    i += 1;
  }
  return out;
}

/** Length in code points of the ANSI escape sequence starting at k, or 0. */
function ansiLength(cps: CP[], k: number): number {
  const first = cps[k]?.cp;
  if (first === 0x9b) return csiFrom(cps, k + 1, k);
  if (first !== 0x1b) return 0;
  const second = cps[k + 1]?.cp;
  if (second === undefined) return 1;
  if (second === 0x5b) return csiFrom(cps, k + 2, k);
  if (second === 0x5d || second === 0x50 || second === 0x5f || second === 0x5e) {
    // OSC / DCS / APC / PM: until BEL or ST (ESC \), bounded.
    for (let j = k + 2; j < cps.length && j < k + 4096; j++) {
      const c = cps[j]?.cp;
      if (c === 0x07) return j - k + 1;
      if (c === 0x1b && cps[j + 1]?.cp === 0x5c) return j - k + 2;
    }
    return Math.min(cps.length, k + 4096) - k;
  }
  return 2;
}

function csiFrom(cps: CP[], start: number, k: number): number {
  for (let j = start; j < cps.length && j < start + 64; j++) {
    const c = cps[j]?.cp ?? 0;
    if (c >= 0x40 && c <= 0x7e) return j - k + 1;
    if (c < 0x20 || c > 0x3f) return j - k;
  }
  return Math.min(cps.length, start + 64) - k;
}

interface Piece { text: string; orig: number }

/** Builds a View from pieces, each mapped to an original offset. */
function makeView(pieces: Piece[], origLength: number): View {
  let text = "";
  const map: number[] = [];
  for (const p of pieces) {
    for (let i = 0; i < p.text.length; i++) map.push(p.orig);
    text += p.text;
  }
  return {
    text,
    toOriginal(i: number) {
      if (i < 0) return 0;
      if (i >= map.length) return origLength;
      return map[i] as number;
    },
  };
}

// ASCII fast paths. Most input is ASCII, and calling normalize() and Unicode-property regexes
// per character dominated scan time (Step 6 bench). The tables are built by the same slow
// functions, so results are identical by construction.
function isWs(ch: string): boolean {
  const c = ch.charCodeAt(0);
  if (ch.length === 1 && c < 0x80) return c === 0x20 || (c >= 0x09 && c <= 0x0d);
  return RE_WS.test(ch);
}

let ASCII_NORM: string[] | null = null;
let ASCII_SKEL: string[] | null = null;
const asciiTable = (fn: (s: string) => string): string[] => initTimed(() => Array.from({ length: 128 }, (_, c) => fn(String.fromCharCode(c))));

function normChar(s: string): string {
  if (s.length === 1 && s.charCodeAt(0) < 0x80) return (ASCII_NORM ??= asciiTable(normCharSlow))[s.charCodeAt(0)] as string;
  return normCharSlow(s);
}

function normCharSlow(s: string): string {
  let cur = s;
  for (let n = 0; n < 4; n++) {
    const next = cur.normalize("NFKC").toLowerCase();
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

function skeletonChar(s: string): string {
  if (s.length === 1 && s.charCodeAt(0) < 0x80) return (ASCII_SKEL ??= asciiTable(skeletonCharSlow))[s.charCodeAt(0)] as string;
  return skeletonCharSlow(s);
}

function skeletonCharSlow(s: string): string {
  let cur = s;
  for (let n = 0; n < 4; n++) {
    let mapped = "";
    for (const ch of cur) {
      const t = confusable(ch.codePointAt(0) ?? 0);
      mapped += t ?? ch;
    }
    let next = "";
    for (const ch of mapped) next += normChar(ch);
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

/** Collapse whitespace runs to one space and trim, keeping the offset mapping. */
function collapse(pieces: Piece[]): Piece[] {
  const out: Piece[] = [];
  let pendingSpace: number | null = null;
  for (const p of pieces) {
    for (const ch of p.text) {
      if (isWs(ch)) {
        if (pendingSpace === null) pendingSpace = p.orig;
        continue;
      }
      if (pendingSpace !== null && out.length > 0) out.push({ text: " ", orig: pendingSpace });
      pendingSpace = null;
      out.push({ text: ch, orig: p.orig });
    }
  }
  return out;
}

export function buildViews(original: string): Views {
  const cps = codePoints(original);
  const facts: Facts = { invisibles: [], bidi: [], tagCount: 0, ansi: 0, comments: false, padding: false };
  const visiblePieces: Piece[] = [];
  let tagDecoded = "";

  for (let k = 0; k < cps.length; k++) {
    const { cp, index, len } = cps[k] as CP;
    const ch = original.slice(index, index + len);

    const ansi = ansiLength(cps, k);
    if (ansi > 0) {
      facts.ansi++;
      k += ansi - 1;
      continue;
    }
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      facts.tagCount++;
      if (cp >= 0xe0020 && cp <= 0xe007e) tagDecoded += String.fromCharCode(cp - 0xe0000);
      continue;
    }
    if (BIDI.has(cp)) {
      const prev = cps[k - 1]?.cp ?? 0;
      const next = cps[k + 1]?.cp ?? 0;
      if (!(MARKS.has(cp) && (isRtl(prev) || isRtl(next)))) facts.bidi.push({ cp, index });
      continue;
    }
    if (cp === 0x200d) {
      // Keep a ZWJ inside an emoji sequence.
      let p = k - 1;
      while (p >= 0 && ((cps[p]?.cp ?? 0) === 0xfe0f || isEmojiModifier(cps[p]?.cp ?? 0))) p--;
      const before = cps[p]?.cp ?? 0;
      const after = cps[k + 1]?.cp ?? 0;
      if (isPicto(before) && isPicto(after)) { visiblePieces.push({ text: ch, orig: index }); continue; }
      facts.invisibles.push({ cp, index });
      continue;
    }
    if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) {
      const prev = cps[k - 1]?.cp ?? 0;
      const keycapBase = prev === 0x23 || prev === 0x2a || (prev >= 0x30 && prev <= 0x39);
      if ((cp === 0xfe0f || cp === 0xfe0e) && (isPicto(prev) || keycapBase)) { visiblePieces.push({ text: ch, orig: index }); continue; }
      facts.invisibles.push({ cp, index });
      continue;
    }
    // ASCII has no Cf characters; its Cc characters are 0x00–0x1f and 0x7f.
    const invisible = cp < 0x80
      ? (cp < 0x20 || cp === 0x7f) && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d
      : HANGUL_FILLERS.has(cp) || cp === 0x034f || RE_CF.test(ch) || (RE_CC.test(ch) && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d);
    if (invisible) {
      facts.invisibles.push({ cp, index });
      continue;
    }
    visiblePieces.push({ text: ch, orig: index });
  }

  const visible = makeView(visiblePieces, original.length);
  const lower = visible.text.toLowerCase();
  facts.comments = lower.includes("<!--") || lower.includes("[//]:") || lower.includes("<!-");

  // Padding: a long run of whitespace followed by more text.
  let nl = 0, wsRun = 0;
  for (const p of visiblePieces) {
    if (isWs(p.text)) {
      wsRun++;
      if (p.text === "\n") nl++;
    } else {
      if (nl >= 20 || wsRun >= 200) facts.padding = true;
      nl = 0;
      wsRun = 0;
    }
  }

  // Per-call caches for non-ASCII characters (ASCII already uses tables): text repeats the same
  // characters, and normalize() per character dominated non-Latin input.
  const normCache = new Map<string, string>();
  const skelCache = new Map<string, string>();
  const cached = (cache: Map<string, string>, fn: (s: string) => string, ch: string): string => {
    if (ch.length === 1 && ch.charCodeAt(0) < 0x80) return fn(ch);
    let r = cache.get(ch);
    if (r === undefined) { r = fn(ch); cache.set(ch, r); }
    return r;
  };
  const normPieces = collapse(visiblePieces.map((p) => ({ text: cached(normCache, normChar, p.text), orig: p.orig })));
  const norm = makeView(normPieces, original.length);
  const skelPieces = collapse(normPieces.map((p) => ({ text: cached(skelCache, skeletonChar, p.text), orig: p.orig })));
  const skeleton = makeView(skelPieces, original.length);

  return { original, visible, norm, skeleton, tagDecoded, facts };
}

/** Norm view text only (used to canonicalize rule phrases at load). */
/** For match.ts's rawNorm: the same per-character NFKC + lowercase as the norm view. */
export { normChar };

export function normText(s: string): string {
  return buildViews(s).norm.text;
}

export function skeletonText(s: string): string {
  return buildViews(s).skeleton.text;
}
