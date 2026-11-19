// Small shared helpers.

/** Deep-freeze plain data (iterative). */
export function deepFreeze<T>(value: T): T {
  const stack: unknown[] = [value];
  const seen = new Set<unknown>();
  while (stack.length > 0) {
    const v = stack.pop();
    if (v === null || typeof v !== "object" || seen.has(v)) continue;
    seen.add(v);
    Object.freeze(v);
    for (const k of Object.keys(v)) stack.push((v as Record<string, unknown>)[k]);
  }
  return value;
}

/**
 * Removes trailing characters in `chars`. Linear time: a regex like /[. ]+$/ backtracks
 * quadratically in V8 on a long run that isn't at the end (a 120 KB path took 27 s).
 */
export function trimEndChars(s: string, chars: string): string {
  let e = s.length;
  while (e > 0 && chars.includes(s[e - 1] as string)) e--;
  return e === s.length ? s : s.slice(0, e);
}

export function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Own data property read on a snapshot (null-prototype) object. */
export function get(v: unknown, key: string): unknown {
  if (!isRecord(v)) return undefined;
  return Object.prototype.hasOwnProperty.call(v, key) ? v[key] : undefined;
}

export function getString(v: unknown, key: string): string | undefined {
  const x = get(v, key);
  return typeof x === "string" ? x : undefined;
}

export function codePointLength(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

/** RFC 6901 pointer segment escaping. */
export function ptrSeg(k: string | number): string {
  return String(k).replace(/~/g, "~0").replace(/\//g, "~1");
}

export function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) { n += 4; i++; }
    else n += 3;
  }
  return n;
}

export function uniq<T>(xs: Iterable<T>): T[] {
  return [...new Set(xs)];
}
