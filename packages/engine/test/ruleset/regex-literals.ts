// Test-only regex analyzer: which literals must every match of a pattern contain?
// Used to prove each regex rule's `anchors` are sound (spec rev 6, Q1).
//
// requiredLiterals(pattern) returns a set S of lowercase strings such that every string the
// pattern matches contains at least one member of S, or null when no such set is known (the
// pattern can match without any literal, e.g. `.*`). It is conservative: when unsure it gives
// up (null) or keeps shorter literals, never claims a literal that some match lacks.
// Matching is compared in lowercase, so case-insensitive patterns are handled too.
//
// Supported syntax (the subset rule regexes use): literals, escapes (\. \- \\ \/ \x.. \u....
// \d \w \s \b \B \n \t \r), classes [...] with ranges and negation, . ^ $, groups ( ) (?: )
// (?i) (?<name> ), alternation, quantifiers ? * + {m} {m,} {m,n} with optional lazy ?.

type Node =
  | { k: "lit"; set: string[] | null } // finite set of single-char alternatives, or null = any char
  | { k: "empty" } // ^ $ \b and flags: match the empty string
  | { k: "cat"; items: Node[] }
  | { k: "alt"; items: Node[] }
  | { k: "rep"; item: Node; min: number; max: number | null };

const MAX_SET = 64; // cap on enumerated strings
const MAX_CLASS = 8; // classes larger than this are treated as "any char"

class Parser {
  i = 0;
  readonly s: string;
  constructor(s: string) { this.s = s; }
  peek(): string | undefined { return this.s[this.i]; }
  eat(c: string): boolean { if (this.s[this.i] === c) { this.i++; return true; } return false; }

  parseAlt(): Node {
    const items = [this.parseCat()];
    while (this.eat("|")) items.push(this.parseCat());
    return items.length === 1 ? items[0] as Node : { k: "alt", items };
  }

  parseCat(): Node {
    const items: Node[] = [];
    while (this.i < this.s.length && this.peek() !== "|" && this.peek() !== ")") items.push(this.parseRep());
    return { k: "cat", items };
  }

  parseRep(): Node {
    let n = this.parseAtom();
    for (;;) {
      const c = this.peek();
      let min: number, max: number | null;
      if (c === "?") { min = 0; max = 1; this.i++; }
      else if (c === "*") { min = 0; max = null; this.i++; }
      else if (c === "+") { min = 1; max = null; this.i++; }
      else if (c === "{" && /^\{\d+(,\d*)?\}/.test(this.s.slice(this.i))) {
        const m = /^\{(\d+)(,(\d*))?\}/.exec(this.s.slice(this.i)) as RegExpExecArray;
        this.i += m[0].length;
        min = Number(m[1]);
        max = m[2] === undefined ? min : m[3] === "" ? null : Number(m[3]);
      } else return n;
      this.eat("?"); // lazy
      n = { k: "rep", item: n, min, max };
    }
  }

  parseAtom(): Node {
    const c = this.s[this.i++];
    if (c === undefined) throw new Error("unexpected end");
    if (c === "(") {
      if (this.s.startsWith("?:", this.i)) this.i += 2;
      else if (this.s.startsWith("?<", this.i) || this.s.startsWith("?P<", this.i)) this.i = this.s.indexOf(">", this.i) + 1;
      else if (this.s[this.i] === "?") {
        // Inline flags like (?i) or (?i:...)
        const m = /^\?([a-zA-Z]+)(\)|:)/.exec(this.s.slice(this.i));
        if (!m) throw new Error(`unsupported group at ${this.i}`);
        this.i += m[0].length;
        if (m[2] === ")") return { k: "empty" };
      }
      const inner = this.parseAlt();
      if (!this.eat(")")) throw new Error("missing )");
      return inner;
    }
    if (c === "[") return this.parseClass();
    if (c === ".") return { k: "lit", set: null };
    if (c === "^" || c === "$") return { k: "empty" };
    if (c === "\\") return this.parseEscape(false) as Node;
    return { k: "lit", set: [c.toLowerCase()] };
  }

  /** In a class, returns a char list (or null for a shorthand class); outside, a Node. */
  parseEscape(inClass: boolean): Node | string[] | null {
    const c = this.s[this.i++];
    if (c === undefined) throw new Error("dangling escape");
    const one = (ch: string) => (inClass ? [ch] : ({ k: "lit", set: [ch] } as Node));
    if (c === "d" || c === "w" || c === "s" || c === "D" || c === "W" || c === "S") return inClass ? null : { k: "lit", set: null };
    if (c === "b" || c === "B" || c === "A" || c === "z") return inClass ? null : { k: "empty" };
    if (c === "n") return one("\n");
    if (c === "t") return one("\t");
    if (c === "r") return one("\r");
    if (c === "x") {
      const m = /^(\{[0-9a-fA-F]+\}|[0-9a-fA-F]{2})/.exec(this.s.slice(this.i)) as RegExpExecArray;
      this.i += m[0].length;
      return one(String.fromCodePoint(parseInt(m[0].replace(/[{}]/g, ""), 16)).toLowerCase());
    }
    if (c === "p" || c === "P") {
      if (this.s[this.i] === "{") this.i = this.s.indexOf("}", this.i) + 1; else this.i++;
      return inClass ? null : { k: "lit", set: null };
    }
    if (/[0-9a-zA-Z]/.test(c)) throw new Error(`unsupported escape \\${c}`);
    return one(c.toLowerCase());
  }

  parseClass(): Node {
    const negated = this.eat("^");
    const chars = new Set<string>();
    let any = negated;
    let first = true;
    while (this.i < this.s.length && (this.peek() !== "]" || first)) {
      first = false;
      let lo: string | null;
      if (this.peek() === "\\") { this.i++; const e = this.parseEscape(true) as string[] | null; if (e === null) { any = true; continue; } lo = e[0] as string; }
      else lo = this.s[this.i++] as string;
      if (this.peek() === "-" && this.s[this.i + 1] !== "]" && this.s[this.i + 1] !== undefined) {
        this.i++;
        let hi = this.s[this.i++] as string;
        if (hi === "\\") hi = ((this.parseEscape(true) as string[] | null) ?? ["￿"])[0] as string;
        const a = lo.codePointAt(0) as number, b = hi.codePointAt(0) as number;
        if (b - a > MAX_CLASS) { any = true; continue; }
        for (let x = a; x <= b; x++) chars.add(String.fromCodePoint(x).toLowerCase());
      } else chars.add(lo.toLowerCase());
    }
    if (!this.eat("]")) throw new Error("missing ]");
    if (any || chars.size > MAX_CLASS) return { k: "lit", set: null };
    return { k: "lit", set: [...chars] };
  }
}

/** Finite set of strings a node can match, or null when too many / unbounded. */
function exact(n: Node): string[] | null {
  switch (n.k) {
    case "empty": return [""];
    case "lit": return n.set;
    case "cat": {
      let acc: string[] = [""];
      for (const it of n.items) {
        const e = exact(it);
        if (e === null) return null;
        const next = new Set<string>();
        for (const a of acc) for (const b of e) next.add(a + b);
        if (next.size > MAX_SET) return null;
        acc = [...next];
      }
      return acc;
    }
    case "alt": {
      const out = new Set<string>();
      for (const it of n.items) { const e = exact(it); if (e === null) return null; for (const x of e) out.add(x); }
      return out.size > MAX_SET ? null : [...out];
    }
    case "rep": {
      if (n.max === null || n.max > 4) return null;
      const e = exact(n.item);
      if (e === null) return null;
      let acc: string[] = n.min === 0 ? [""] : [];
      let cur: string[] = [""];
      for (let r = 1; r <= n.max; r++) {
        const next = new Set<string>();
        for (const a of cur) for (const b of e) next.add(a + b);
        if (next.size > MAX_SET) return null;
        cur = [...next];
        if (r >= n.min) acc = [...new Set([...acc, ...cur])];
      }
      return acc.length > MAX_SET ? null : acc;
    }
  }
}

/**
 * Ranks candidate requirement sets. With `anchors`, a set whose every literal contains an
 * anchor beats any set that isn't covered (several different sets can all be required; we
 * want one the declared anchors prove). Then longer shortest-literal wins.
 */
function scorer(anchors?: readonly string[]) {
  return (s: string[] | null): number => {
    if (s === null || s.length === 0 || s.includes("")) return -1;
    const len = Math.min(...s.map((x) => x.length));
    const covered = anchors !== undefined && s.every((lit) => anchors.some((a) => lit.includes(a)));
    return (covered ? 1_000_000 : 0) + len;
  };
}

/** A required-literal set for n (see file header), or null. */
function required(n: Node, anchors?: readonly string[]): string[] | null {
  const score = scorer(anchors);
  const e = exact(n);
  if (e !== null && !e.includes("") && (anchors === undefined || score(e) >= 1_000_000)) return e;
  switch (n.k) {
    case "cat": {
      // Candidates: each child's own requirement, and every run of consecutive finite children
      // concatenated (their cross product is required as a contiguous substring).
      let best: string[] | null = null;
      const consider = (c: string[] | null) => { if (c !== null && !c.includes("") && score(c) > score(best)) best = c; };
      if (e !== null && !e.includes("")) consider(e);
      for (const it of n.items) consider(required(it, anchors));
      for (let a = 0; a < n.items.length; a++) {
        let acc: string[] = [""];
        for (let b = a; b < n.items.length; b++) {
          const eb = exact(n.items[b] as Node);
          if (eb === null) break;
          const next = new Set<string>();
          for (const x of acc) for (const y of eb) next.add(x + y);
          if (next.size > MAX_SET) break;
          acc = [...next];
          consider(acc);
        }
      }
      return best;
    }
    case "alt": {
      const out = new Set<string>();
      for (const it of n.items) { const r = required(it, anchors); if (r === null) return null; for (const x of r) out.add(x); }
      return [...out];
    }
    case "rep": return n.min >= 1 ? required(n.item, anchors) : null;
    default: return e !== null && !e.includes("") ? e : null;
  }
}

export function requiredLiterals(pattern: string, anchors?: readonly string[]): string[] | null {
  const p = new Parser(pattern);
  const n = p.parseAlt();
  if (p.i !== pattern.length) throw new Error(`unparsed input at ${p.i} in ${pattern}`);
  const r = required(n, anchors);
  return r === null || r.length === 0 || r.includes("") ? null : r;
}

/** True when every required literal contains one of the anchors (so every match does). */
export function anchorsCover(pattern: string, anchors: readonly string[]): { ok: boolean; uncovered: string[] } {
  const req = requiredLiterals(pattern, anchors);
  if (req === null) return { ok: false, uncovered: ["<pattern has no required literal>"] };
  const uncovered = req.filter((lit) => !anchors.some((a) => lit.includes(a)));
  return { ok: uncovered.length === 0, uncovered };
}
