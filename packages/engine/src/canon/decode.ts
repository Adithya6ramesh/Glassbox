// C5: find encoded blobs with a linear scanner and decode them.
// Kept only if the result is valid UTF-8 with ≥ 80% printable code points.
import { trimEndChars } from "../util/misc.js";

export interface Decoded { start: number; end: number; via: "base64" | "hex" | "url"; text: string }

const B64 = new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=");
const HEX = new Set("0123456789abcdefABCDEF");

function hasMixedB64(run: string): boolean {
  let letters = false, other = false;
  for (let k = 0; k < run.length; k++) {
    const c = run.charCodeAt(k);
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) letters = true;
    else other = true;
    if (letters && other) return true;
  }
  // All letters: still plausible if it mixes case.
  return run !== run.toLowerCase() && run !== run.toUpperCase();
}

function printableRatio(s: string): number {
  if (s.length === 0) return 0;
  let ok = 0, n = 0;
  for (const ch of s) {
    n++;
    const c = ch.codePointAt(0) ?? 0;
    if (c === 0x09 || c === 0x0a || c === 0x0d || (c >= 0x20 && c !== 0x7f && !(c >= 0x80 && c <= 0x9f) && c !== 0xfffd)) ok++;
  }
  return ok / n;
}

function utf8Strict(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function decodeBase64(s: string): Uint8Array | null {
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  t = trimEndChars(t, "=");
  if (t.length % 4 === 1) return null;
  while (t.length % 4 !== 0) t += "=";
  try {
    const bin = atob(t);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function accept(bytes: Uint8Array | null): string | null {
  if (!bytes || bytes.length < 8) return null;
  const s = utf8Strict(bytes);
  if (s === null || printableRatio(s) < 0.8) return null;
  return s;
}

export function findDecodable(text: string, budget: { bytes: number }): Decoded[] {
  const out: Decoded[] = [];
  const n = text.length;
  let i = 0;
  while (i < n && budget.bytes > 0) {
    const c = text[i] as string;
    // base64 / base64url run
    if (B64.has(c)) {
      let j = i;
      let allHex = true;
      while (j < n && B64.has(text[j] as string)) { if (!HEX.has(text[j] as string)) allHex = false; j++; }
      const run = text.slice(i, j);
      if (allHex && run.length >= 32 && run.length % 2 === 0) {
        const bytes = new Uint8Array(run.length / 2);
        for (let k = 0; k < bytes.length; k++) bytes[k] = parseInt(run.slice(k * 2, k * 2 + 2), 16);
        const s = accept(bytes);
        if (s !== null) { out.push({ start: i, end: j, via: "hex", text: s }); budget.bytes -= s.length; }
      } else if (run.length >= 20) {
        // `key=<base64>`: an "=" followed by more base64 characters isn't padding, so
        // try each "="-separated piece as well as the whole run.
        const pieces: { s: string; off: number }[] = [{ s: run, off: 0 }];
        let off = 0;
        for (const part of run.split("=")) {
          if (part.length >= 20) pieces.push({ s: run.slice(off, off + part.length) + (() => { const rest = run.slice(off + part.length, off + part.length + 2); let k = 0; while (k < rest.length && rest[k] === "=") k++; return rest.slice(0, k); })(), off });
          off += part.length + 1;
        }
        for (const piece of pieces) {
          if (piece.s.length < 20 || !hasMixedB64(piece.s)) continue;
          const s = accept(decodeBase64(piece.s));
          if (s !== null) { out.push({ start: i + piece.off, end: i + piece.off + piece.s.length, via: "base64", text: s }); budget.bytes -= s.length; break; }
        }
      }
      i = j > i ? j : i + 1;
      continue;
    }
    // percent-encoding: ≥ 3 %XX triplets in a 64-char window
    if (c === "%") {
      let j = i, triplets = 0;
      while (j < n && j - i < 512) {
        if (text[j] === "%" && HEX.has(text[j + 1] ?? "") && HEX.has(text[j + 2] ?? "")) { triplets++; j += 3; }
        else if (/[A-Za-z0-9._~+-]/.test(text[j] as string)) j++;
        else break;
      }
      if (triplets >= 3) {
        try {
          const s = decodeURIComponent(text.slice(i, j));
          if (printableRatio(s) >= 0.8) { out.push({ start: i, end: j, via: "url", text: s }); budget.bytes -= s.length; }
        } catch { /* not decodable */ }
      }
      i = j > i ? j : i + 1;
      continue;
    }
    i++;
  }
  return out;
}
