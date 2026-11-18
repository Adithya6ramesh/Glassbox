// RFC 8785 JSON Canonicalization Scheme, hand-written (engine-spec §12.8).
// Works on snapshot values (null-prototype objects, arrays, strings, finite numbers,
// booleans, null). Iterative, so input depth can't overflow the stack.

export class JcsError extends Error {}

function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new JcsError("non-finite number");
  // ECMAScript Number::toString is exactly the RFC 8785 number format.
  return Object.is(n, -0) ? "0" : String(n);
}

/** Compare by UTF-16 code units, as RFC 8785 §3.2.3 requires. */
function compareKeys(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

type Frame =
  | { kind: "value"; v: unknown }
  | { kind: "text"; s: string };

export function jcs(value: unknown): string {
  const parts: string[] = [];
  const stack: Frame[] = [{ kind: "value", v: value }];
  let steps = 0;
  while (stack.length > 0) {
    if (++steps > 5_000_000) throw new JcsError("too large");
    const f = stack.pop() as Frame;
    if (f.kind === "text") { parts.push(f.s); continue; }
    const v = f.v;
    if (v === null) parts.push("null");
    else if (typeof v === "boolean") parts.push(v ? "true" : "false");
    else if (typeof v === "number") parts.push(serializeNumber(v));
    else if (typeof v === "string") parts.push(serializeString(v));
    else if (Array.isArray(v)) {
      const frames: Frame[] = [{ kind: "text", s: "[" }];
      v.forEach((x: unknown, i: number) => {
        if (i > 0) frames.push({ kind: "text", s: "," });
        frames.push({ kind: "value", v: x });
      });
      frames.push({ kind: "text", s: "]" });
      for (let i = frames.length - 1; i >= 0; i--) stack.push(frames[i] as Frame);
    } else if (typeof v === "object") {
      const o = v as Record<string, unknown>;
      const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort(compareKeys);
      const frames: Frame[] = [{ kind: "text", s: "{" }];
      keys.forEach((k, i) => {
        frames.push({ kind: "text", s: (i > 0 ? "," : "") + serializeString(k) + ":" });
        frames.push({ kind: "value", v: o[k] });
      });
      frames.push({ kind: "text", s: "}" });
      for (let i = frames.length - 1; i >= 0; i--) stack.push(frames[i] as Frame);
    } else {
      throw new JcsError("non-JSON value");
    }
  }
  return parts.join("");
}
