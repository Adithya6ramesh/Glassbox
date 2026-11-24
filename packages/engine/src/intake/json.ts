// C1–C2: strict, bounded, iterative JSON parser.
// - builds null-prototype objects; __proto__/constructor/prototype are plain data (CP-PARSE-003)
// - duplicate keys are kept as "key~dupN" (CP-PARSE-001)
// - lone surrogates (escaped or raw) are flagged (CP-PARSE-005)
// - invalid UTF-8 bytes are flagged (CP-PARSE-002); a BOM is stripped
// - depth and node limits stop the parse (CP-LIMIT-002 / CP-LIMIT-003)
// Never recurses on input structure and never throws for bad input.

export interface IntakeIssue { code: string; pointer?: string }
export interface ParseResult { ok: boolean; value: unknown; issues: IntakeIssue[]; degraded: boolean }
export interface ParseOptions { maxDepth?: number; maxNodes?: number; maxStringBytes?: number }

const PROTO_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function decode(input: string | Uint8Array, issues: IntakeIssue[]): string {
  if (typeof input === "string") return input;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    issues.push({ code: "CP-PARSE-002" });
    return new TextDecoder("utf-8", { fatal: false }).decode(input);
  }
}

class Fail extends Error {
  constructor(readonly code: string) { super(code); }
}

type Container =
  | { kind: "array"; value: unknown[]; pointer: string }
  | { kind: "object"; value: Record<string, unknown>; pointer: string; key: string | null; seen: Map<string, number> };

export function parseJsonStrict(input: string | Uint8Array, opts: ParseOptions = {}): ParseResult {
  const issues: IntakeIssue[] = [];
  const maxDepth = opts.maxDepth ?? 32;
  const maxNodes = opts.maxNodes ?? 100_000;
  let text = decode(input, issues);
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  let i = 0;
  let nodes = 0;
  const stack: Container[] = [];
  let root: unknown = undefined;
  let haveRoot = false;

  const ws = () => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const readString = (pointer: string): string => {
    // text[i] === '"'
    i++;
    let out = "";
    let start = i;
    while (true) {
      if (i >= text.length) throw new Fail("CP-PARSE-008");
      const c = text.charCodeAt(i);
      if (c === 0x22) { out += text.slice(start, i); i++; break; }
      if (c < 0x20) throw new Fail("CP-PARSE-008");
      if (c >= 0xd800 && c <= 0xdfff) {
        const isHigh = c <= 0xdbff;
        const next = text.charCodeAt(i + 1);
        if (!(isHigh && next >= 0xdc00 && next <= 0xdfff)) issues.push({ code: "CP-PARSE-005", pointer });
        else { i += 2; continue; }
      }
      if (c === 0x5c) {
        out += text.slice(start, i);
        const e = text[i + 1];
        i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Fail("CP-PARSE-008");
            const cu = parseInt(hex, 16);
            i += 4;
            if (cu >= 0xd800 && cu <= 0xdbff) {
              const lo = text.slice(i, i + 6);
              if (/^\\u[dD][c-fC-F][0-9a-fA-F]{2}$/.test(lo)) {
                out += String.fromCharCode(cu, parseInt(lo.slice(2), 16));
                i += 6;
                break;
              }
              issues.push({ code: "CP-PARSE-005", pointer });
            } else if (cu >= 0xdc00 && cu <= 0xdfff) {
              issues.push({ code: "CP-PARSE-005", pointer });
            }
            out += String.fromCharCode(cu);
            break;
          }
          default: throw new Fail("CP-PARSE-008");
        }
        start = i;
        continue;
      }
      i++;
    }
    return out;
  };

  const readNumber = (): number => {
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i, i + 400));
    if (!m) throw new Fail("CP-PARSE-008");
    i += m[0].length;
    const n = Number(m[0]);
    return Number.isFinite(n) ? n : 0;
  };

  const ptrSeg = (k: string | number) => String(k).replace(/~/g, "~0").replace(/\//g, "~1");

  const attach = (v: unknown) => {
    const top = stack[stack.length - 1];
    if (!top) { root = v; haveRoot = true; return; }
    if (top.kind === "array") top.value.push(v);
    else {
      const key = top.key as string;
      let k = key;
      const n = top.seen.get(key) ?? 0;
      if (n > 0) {
        k = `${key}~dup${n}`;
        issues.push({ code: "CP-PARSE-001", pointer: `${top.pointer}/${ptrSeg(key)}` });
      }
      top.seen.set(key, n + 1);
      Object.defineProperty(top.value, k, { value: v, enumerable: true, writable: true, configurable: true });
      top.key = null;
    }
  };

  const childPointer = (): string => {
    const top = stack[stack.length - 1];
    if (!top) return "";
    if (top.kind === "array") return `${top.pointer}/${top.value.length}`;
    return `${top.pointer}/${ptrSeg(top.key ?? "")}`;
  };

  try {
    ws();
    while (!haveRoot) {
      ws();
      const top = stack[stack.length - 1];
      // Expecting a key?
      if (top && top.kind === "object" && top.key === null) {
        if (text[i] === "}") { i++; stack.pop(); attach(top.value); if (stack.length === 0) break; afterValue(); continue; }
        if (text[i] !== '"') throw new Fail("CP-PARSE-008");
        const key = readString(top.pointer);
        if (PROTO_KEYS.has(key)) issues.push({ code: "CP-PARSE-003", pointer: `${top.pointer}/${ptrSeg(key)}` });
        ws();
        if (text[i] !== ":") throw new Fail("CP-PARSE-008");
        i++;
        top.key = key;
        continue;
      }
      if (top && top.kind === "array" && text[i] === "]" && top.value.length === 0) {
        i++; stack.pop(); attach(top.value); if (stack.length === 0) break; afterValue(); continue;
      }
      // A value.
      if (++nodes > maxNodes) throw new Fail("CP-LIMIT-003");
      const c = text[i];
      const pointer = childPointer();
      if (c === "{" || c === "[") {
        if (stack.length >= maxDepth) throw new Fail("CP-LIMIT-002");
        i++;
        if (c === "{") stack.push({ kind: "object", value: Object.create(null) as Record<string, unknown>, pointer, key: null, seen: new Map() });
        else stack.push({ kind: "array", value: [], pointer });
        continue;
      }
      let v: unknown;
      if (c === '"') v = readString(pointer);
      else if (c === "t" && text.startsWith("true", i)) { v = true; i += 4; }
      else if (c === "f" && text.startsWith("false", i)) { v = false; i += 5; }
      else if (c === "n" && text.startsWith("null", i)) { v = null; i += 4; }
      else if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) v = readNumber();
      else throw new Fail("CP-PARSE-008");
      attach(v);
      if (stack.length === 0) break;
      afterValue();
    }
    ws();
    if (i !== text.length || !haveRoot) throw new Fail("CP-PARSE-008");
    return { ok: true, value: root, issues, degraded: false };
  } catch (e) {
    const code = e instanceof Fail ? e.code : "CP-PARSE-008";
    issues.push({ code });
    return { ok: false, value: undefined, issues, degraded: true };
  }

  function afterValue() {
    ws();
    const top = stack[stack.length - 1];
    if (!top) return;
    const c = text[i];
    if (c === ",") {
      i++;
      ws();
      if (top.kind === "array" && text[i] === "]") throw new Fail("CP-PARSE-008");
      if (top.kind === "object" && text[i] === "}") throw new Fail("CP-PARSE-008");
      return;
    }
    if ((top.kind === "array" && c === "]") || (top.kind === "object" && c === "}")) {
      i++;
      stack.pop();
      attach(top.value);
      if (stack.length > 0) afterValue();
      return;
    }
    throw new Fail("CP-PARSE-008");
  }
}
