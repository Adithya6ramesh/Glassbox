// Linear-time regex: every pattern applied to untrusted text goes
// through re2js. Compiled patterns are cached per pattern string (bounded cache).
import { RE2JS } from "re2js";
import { initTimed } from "./initclock.js";

type Compiled = ReturnType<typeof RE2JS.compile>;
const cache = new Map<string, Compiled | null>();

export function compile(pattern: string, flags?: "i"): Compiled | null {
  const key = (flags ?? "") + "\u0000" + pattern;
  if (cache.has(key)) return cache.get(key) ?? null;
  let c: Compiled | null;
  try {
    c = initTimed(() => RE2JS.compile(flags === "i" ? `(?i)${pattern}` : pattern));
  } catch {
    c = null;
  }
  if (cache.size > 2000) cache.clear();
  cache.set(key, c);
  return c;
}

export interface ReMatch { start: number; end: number; text: string; groups: (string | null)[] }

export function findAll(pattern: string, text: string, flags?: "i", max = 200): ReMatch[] {
  const re = compile(pattern, flags);
  if (!re) return [];
  const m = re.matcher(text);
  const out: ReMatch[] = [];
  while (out.length < max && m.find()) {
    const groups: (string | null)[] = [];
    for (let g = 1; g <= m.groupCount(); g++) groups.push(m.group(g));
    out.push({ start: m.start(), end: m.end(), text: m.group() ?? "", groups });
    if (m.end() === m.start() && m.end() >= text.length) break;
  }
  return out;
}

export function test(pattern: string, text: string, flags?: "i"): boolean {
  const re = compile(pattern, flags);
  if (!re) return false;
  return re.matcher(text).find();
}

export function isValidPattern(pattern: string): boolean {
  return compile(pattern) !== null;
}
