// Hand-written bash/sh parser (engine-spec §7.3, Q2). Recursive descent over a defined
// subset, bounded (bytes, nesting, tokens). Anything outside the subset → unanalyzable.

export const MAX_NESTING = 8;
export const MAX_TOKENS = 4096;

/** One piece of a word. */
export type Part =
  | { t: "lit"; s: string; quoted: boolean }
  | { t: "var"; name: string; braced: boolean; quoted: boolean }
  | { t: "subst"; script: Script; quoted: boolean }
  | { t: "arith"; raw: string }
  | { t: "glob"; s: string }
  | { t: "tilde"; user: string };

export interface Word {
  parts: Part[];
  /** Raw source text of the word. */
  raw: string;
  /** Unquoted `{a,b}` / `{a..b}` present. */
  brace: boolean;
}

export interface Redirect {
  op: string; // > >> < <> >| &> &>> >& <& << <<- <<<
  fd: number | null;
  target: Word | null; // null for heredocs
  heredoc?: { body: string; quoted: boolean; script: Script | null };
}

export interface SimpleCommand {
  kind: "simple";
  assigns: { name: string; value: Word | null; raw: string }[];
  words: Word[];
  redirects: Redirect[];
  /** stdin comes from the previous pipeline stage. */
  pipedIn: boolean;
  /** Words of the previous pipeline stage's command (for curl | sh detection). */
  pipedFrom: SimpleCommand | null;
}

export interface Script {
  commands: SimpleCommand[];
  /** Function names defined in this script. */
  functions: string[];
  /** Order of `cd` effects is approximated by command order. */
}

export class Unanalyzable extends Error {
  constructor(readonly reason: string) { super(reason); }
}

const META = new Set([" ", "\t", "\n", ";", "&", "|", "(", ")", "<", ">"]);
const RESERVED_UNSUPPORTED = new Set(["case", "esac", "select", "coproc", "until_unsupported"]);

function isNameStart(c: string | undefined): boolean {
  return c !== undefined && ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_");
}
function isNameChar(c: string | undefined): boolean {
  return isNameStart(c) || (c !== undefined && c >= "0" && c <= "9");
}

export interface ParseOptions { maxBytes: number }

export function parseShell(src: string, opts: ParseOptions = { maxBytes: 16 * 1024 }): Script {
  if (src.length > opts.maxBytes) throw new Unanalyzable("command longer than the analysis limit");
  const p = new Parser(src, 0);
  const script = p.parseScript(null);
  if (p.i < src.length) throw new Unanalyzable(`unexpected '${src[p.i]}'`);
  return script;
}

class Parser {
  i = 0;
  tokens = 0;
  pendingHeredocs: Redirect[] = [];
  constructor(readonly src: string, readonly depth: number) {
    if (depth > MAX_NESTING) throw new Unanalyzable("nesting too deep");
  }

  private peek(k = 0): string | undefined { return this.src[this.i + k]; }
  private bump(): void { if (++this.tokens > MAX_TOKENS) throw new Unanalyzable("too many tokens"); }

  /** Skip blanks and comments (not newlines). Handles line continuations. */
  private blanks(): void {
    while (this.i < this.src.length) {
      const c = this.src[this.i];
      if (c === " " || c === "\t") { this.i++; continue; }
      if (c === "\\" && this.src[this.i + 1] === "\n") { this.i += 2; continue; }
      if (c === "#") { while (this.i < this.src.length && this.src[this.i] !== "\n") this.i++; continue; }
      break;
    }
  }

  private newline(): boolean {
    if (this.src[this.i] !== "\n") return false;
    this.i++;
    this.readHeredocBodies();
    return true;
  }

  private readHeredocBodies(): void {
    const pending = this.pendingHeredocs;
    this.pendingHeredocs = [];
    for (const r of pending) {
      const h = r.heredoc as NonNullable<Redirect["heredoc"]>;
      const delim = (r as Redirect & { delim: string }).delim;
      const stripTabs = r.op === "<<-";
      const lines: string[] = [];
      let found = false;
      while (this.i <= this.src.length) {
        let nl = this.src.indexOf("\n", this.i);
        if (nl < 0) nl = this.src.length;
        let line = this.src.slice(this.i, nl);
        this.i = Math.min(nl + 1, this.src.length + 1);
        if (stripTabs) line = line.replace(/^\t+/, "");
        if (line === delim) { found = true; break; }
        lines.push(line);
        if (nl >= this.src.length) break;
      }
      if (this.i > this.src.length) this.i = this.src.length;
      if (!found) throw new Unanalyzable("here-doc without its terminator");
      h.body = lines.join("\n") + (lines.length ? "\n" : "");
      if (!h.quoted) h.script = expansionsOfHeredoc(h.body, this.depth);
    }
  }

  /** Parse a list of and-or items until `stop` (")" , "}" , keyword set) or EOF. */
  parseScript(stop: string | null, stopWords: Set<string> | null = null): Script {
    const script: Script = { commands: [], functions: [] };
    for (;;) {
      this.blanks();
      if (this.i >= this.src.length) break;
      const c = this.peek();
      if (c === "\n") { this.newline(); continue; }
      if (c === ";" ) {
        if (this.peek(1) === ";") throw new Unanalyzable("case syntax is not supported");
        this.i++;
        continue;
      }
      if (stop !== null && c === stop) break;
      if (stopWords && this.atWord(stopWords)) break;
      if (c === ")" || c === "&" || c === "|") throw new Unanalyzable(`unexpected '${c}'`);
      this.parseAndOr(script);
      this.blanks();
      const d = this.peek();
      if (d === ";" && this.peek(1) !== ";") { this.i++; continue; }
      if (d === "&" && this.peek(1) !== "&" && this.peek(1) !== ">") { this.i++; continue; }
      if (d === "\n") { this.newline(); continue; }
      if (d === undefined) break;
      if (stop !== null && d === stop) break;
      if (stopWords && this.atWord(stopWords)) break;
      throw new Unanalyzable(`unexpected '${d}'`);
    }
    if (this.pendingHeredocs.length > 0) throw new Unanalyzable("here-doc without a body");
    return script;
  }

  /** Is the next word exactly one of `words` (followed by a metachar or EOF)? */
  private atWord(words: Set<string>): string | null {
    for (const w of words) {
      if (this.src.startsWith(w, this.i)) {
        const after = this.src[this.i + w.length];
        if (after === undefined || META.has(after)) return w;
      }
    }
    return null;
  }

  private expectWord(w: string): void {
    this.blanksAndNewlines();
    if (!this.atWord(new Set([w]))) throw new Unanalyzable(`expected '${w}'`);
    this.i += w.length;
  }

  private blanksAndNewlines(): void {
    for (;;) {
      this.blanks();
      if (this.peek() === "\n") { this.newline(); continue; }
      if (this.peek() === ";" && this.peek(1) !== ";") { this.i++; continue; }
      break;
    }
  }

  private parseAndOr(script: Script): void {
    this.parsePipeline(script);
    for (;;) {
      this.blanks();
      if ((this.peek() === "&" && this.peek(1) === "&") || (this.peek() === "|" && this.peek(1) === "|")) {
        this.i += 2;
        this.bump();
        this.blanksAndNewlinesOnly();
        if (this.i >= this.src.length) throw new Unanalyzable("command list ends with an operator");
        this.parsePipeline(script);
        continue;
      }
      break;
    }
  }

  private blanksAndNewlinesOnly(): void {
    for (;;) {
      this.blanks();
      if (this.peek() === "\n") { this.newline(); continue; }
      break;
    }
  }

  private parsePipeline(script: Script): void {
    this.blanks();
    if (this.peek() === "!" && (this.peek(1) === " " || this.peek(1) === "\t")) { this.i++; this.blanks(); }
    if (this.atWord(new Set(["time"]))) {
      this.i += 4;
      this.blanks();
      if (this.src.startsWith("-p", this.i) && META.has(this.src[this.i + 2] ?? " ")) { this.i += 2; this.blanks(); }
    }
    let prev: SimpleCommand | null = null;
    let first = true;
    for (;;) {
      const before = script.commands.length;
      this.parseCommand(script);
      const last = script.commands[script.commands.length - 1];
      if (!first && last && script.commands.length > before) {
        // The first simple command of this stage reads from the pipe.
        const head = script.commands[before];
        if (head) { head.pipedIn = true; head.pipedFrom = prev; }
      }
      prev = last ?? null;
      first = false;
      this.blanks();
      if (this.peek() === "|" && this.peek(1) !== "|") {
        this.i += this.peek(1) === "&" ? 2 : 1;
        this.bump();
        this.blanksAndNewlinesOnly();
        if (this.i >= this.src.length) throw new Unanalyzable("pipeline ends with '|'");
        continue;
      }
      break;
    }
  }

  private parseCommand(script: Script): void {
    this.blanks();
    const c = this.peek();
    if (c === "(") {
      if (this.peek(1) === "(") throw new Unanalyzable("(( )) arithmetic commands are not supported");
      this.i++;
      const inner = new Parser(this.src, this.depth + 1);
      inner.i = this.i;
      inner.tokens = this.tokens;
      const s = inner.parseScript(")");
      if (inner.peek() !== ")") throw new Unanalyzable("unclosed subshell");
      this.i = inner.i + 1;
      this.tokens = inner.tokens;
      this.absorb(script, s);
      this.trailingRedirects(script, before(script, s));
      return;
    }
    const kw = this.atWord(new Set(["{", "if", "for", "while", "until", "function", "case", "select", "coproc", "[[", "}"]));
    if (kw === "}" ) throw new Unanalyzable("unexpected '}'");
    // A reserved word that closes or continues a compound command, where a command is
    // expected, is a syntax error in bash (T-DIFF: `…; then x; fi` without an `if`).
    const stray = this.atWord(new Set(["then", "else", "elif", "fi", "do", "done", "esac"]));
    if (stray) throw new Unanalyzable(`unexpected '${stray}'`);
    if (kw && RESERVED_UNSUPPORTED.has(kw)) throw new Unanalyzable(`'${kw}' is not supported`);
    if (kw === "{") {
      this.i += 1;
      const s = this.sub(() => this.parseScript(null, new Set(["}"])));
      this.expectWord("}");
      this.absorb(script, s);
      this.trailingRedirects(script, before(script, s));
      return;
    }
    if (kw === "if") {
      this.i += 2;
      const stops = new Set(["then"]);
      this.absorb(script, this.sub(() => this.parseScript(null, stops)));
      this.expectWord("then");
      for (;;) {
        const body = this.sub(() => this.parseScript(null, new Set(["elif", "else", "fi"])));
        this.absorb(script, body);
        this.blanksAndNewlines();
        const w = this.atWord(new Set(["elif", "else", "fi"]));
        if (w === "fi") { this.i += 2; break; }
        if (w === "else") { this.i += 4; continue; }
        if (w === "elif") {
          this.i += 4;
          this.absorb(script, this.sub(() => this.parseScript(null, new Set(["then"]))));
          this.expectWord("then");
          continue;
        }
        throw new Unanalyzable("unterminated if");
      }
      return;
    }
    if (kw === "while" || kw === "until") {
      this.i += kw.length;
      this.absorb(script, this.sub(() => this.parseScript(null, new Set(["do"]))));
      this.expectWord("do");
      this.absorb(script, this.sub(() => this.parseScript(null, new Set(["done"]))));
      this.expectWord("done");
      return;
    }
    if (kw === "for") {
      this.i += 3;
      this.blanks();
      if (this.peek() === "(") throw new Unanalyzable("C-style for loops are not supported");
      const name = this.readWord();
      if (!name || !isPlainName(name)) throw new Unanalyzable("bad for loop");
      this.blanksAndNewlinesOnly();
      const loopWords: Word[] = [];
      if (this.atWord(new Set(["in"]))) {
        this.i += 2;
        for (;;) {
          this.blanks();
          const ch = this.peek();
          if (ch === undefined || ch === ";" || ch === "\n") break;
          const w = this.readWord();
          if (!w) throw new Unanalyzable("bad for loop");
          loopWords.push(w);
        }
      }
      // Loop words become a pseudo-command so their substitutions are analyzed.
      if (loopWords.length) script.commands.push({ kind: "simple", assigns: [], words: [{ parts: [{ t: "lit", s: "true", quoted: false }], raw: "true", brace: false }, ...loopWords], redirects: [], pipedIn: false, pipedFrom: null, });
      this.expectWord("do");
      this.absorb(script, this.sub(() => this.parseScript(null, new Set(["done"]))));
      this.expectWord("done");
      return;
    }
    if (kw === "function") {
      this.i += 8;
      this.blanks();
      const name = this.readWord();
      if (!name || !isPlainName(name)) throw new Unanalyzable("bad function definition");
      this.blanks();
      if (this.peek() === "(" && this.peek(1) === ")") { this.i += 2; }
      this.blanksAndNewlinesOnly();
      this.functionBody(script, plainText(name));
      return;
    }
    if (kw === "[[") {
      this.i += 2;
      const end = this.src.indexOf("]]", this.i);
      if (end < 0) throw new Unanalyzable("unterminated [[");
      const inner = this.src.slice(this.i, end);
      if (inner.includes("$(") || inner.includes("`") || inner.includes("<(")) throw new Unanalyzable("substitution inside [[ ]]");
      this.i = end + 2;
      script.commands.push({ kind: "simple", assigns: [], words: [litWord("[[")], redirects: [], pipedIn: false, pipedFrom: null });
      return;
    }
    // Simple command (or `name() { … }` function definition).
    this.simpleCommand(script);
  }

  private nest = 0;
  private sub(fn: () => Script): Script {
    if (this.depth + ++this.nest > MAX_NESTING) throw new Unanalyzable("nesting too deep");
    try {
      return fn();
    } finally {
      this.nest--;
    }
  }

  private absorb(into: Script, s: Script): void {
    into.commands.push(...s.commands);
    into.functions.push(...s.functions);
  }

  private trailingRedirects(script: Script, firstIdx: number): void {
    // Redirects after a compound command apply to all its commands.
    const reds: Redirect[] = [];
    for (;;) {
      this.blanks();
      const r = this.tryRedirect();
      if (!r) break;
      reds.push(r);
    }
    if (reds.length) for (let k = firstIdx; k < script.commands.length; k++) script.commands[k]?.redirects.push(...reds);
  }

  private functionBody(script: Script, name: string): void {
    this.blanksAndNewlinesOnly();
    const c = this.peek();
    let body: Script;
    if (c === "{" && META.has(this.peek(1) ?? " ")) {
      this.i++;
      body = this.sub(() => this.parseScript(null, new Set(["}"])));
      this.expectWord("}");
    } else if (c === "(") {
      this.i++;
      body = this.sub(() => this.parseScript(")"));
      if (this.peek() !== ")") throw new Unanalyzable("bad function body");
      this.i++;
    } else throw new Unanalyzable("unsupported function body");
    script.functions.push(name);
    this.absorb(script, body);
  }

  private simpleCommand(script: Script): void {
    const cmd: SimpleCommand = { kind: "simple", assigns: [], words: [], redirects: [], pipedIn: false, pipedFrom: null };
    for (;;) {
      this.blanks();
      const c = this.peek();
      if (c === undefined || c === "\n" || c === ";" || c === "&" && this.peek(1) !== ">" || c === "|" || c === ")") break;
      if (c === "(" ) {
        // name() { … }
        if (cmd.words.length === 1 && cmd.assigns.length === 0 && this.peek(1) === ")") {
          const name = plainText(cmd.words[0] as Word);
          if (!isPlainNameStr(name)) throw new Unanalyzable("bad function name");
          this.i += 2;
          this.functionBody(script, name);
          return;
        }
        throw new Unanalyzable("unexpected '('");
      }
      const r = this.tryRedirect();
      if (r) { cmd.redirects.push(r); continue; }
      // Assignment (only before the command name).
      if (cmd.words.length === 0 && isNameStart(c)) {
        let j = this.i;
        while (isNameChar(this.src[j])) j++;
        if (this.src[j] === "[") { const close = this.src.indexOf("]", j); if (close > 0) j = close + 1; }
        if (this.src[j] === "+" && this.src[j + 1] === "=") j++;
        if (this.src[j] === "=") {
          const raw = this.src.slice(this.i, j);
          const plus = raw.endsWith("+") ? raw.slice(0, -1) : raw;
          const name = plus.includes("[") ? plus.slice(0, plus.indexOf("[")) : plus;
          this.i = j + 1;
          if (this.peek() === "(") throw new Unanalyzable("array assignment is not supported");
          const start = this.i;
          const value = META.has(this.peek() ?? " ") ? null : this.readWord(true);
          cmd.assigns.push({ name, value, raw: this.src.slice(start, this.i) });
          this.bump();
          continue;
        }
      }
      const w = this.readWord();
      if (!w) throw new Unanalyzable(`unexpected '${c}'`);
      cmd.words.push(w);
      this.bump();
    }
    if (cmd.words.length === 0 && cmd.assigns.length === 0 && cmd.redirects.length === 0) throw new Unanalyzable("empty command");
    script.commands.push(cmd);
  }

  private tryRedirect(): Redirect | null {
    const s = this.src;
    let j = this.i;
    let fd: number | null = null;
    while (s[j] !== undefined && s[j] as string >= "0" && s[j] as string <= "9") j++;
    if (j > this.i && (s[j] === "<" || s[j] === ">")) fd = Number(s.slice(this.i, j));
    else j = this.i;
    const ops = ["&>>", "&>", "<<<", "<<-", "<<", "<>", ">>", ">|", ">&", "<&", ">", "<"];
    const op = ops.find((o) => s.startsWith(o, j));
    if (!op) return null;
    if ((op === ">" || op === "<") && s[j + 1] === "(") throw new Unanalyzable("process substitution");
    this.i = j + op.length;
    this.bump();
    this.blanks();
    if (op === "<<" || op === "<<-") {
      const start = this.i;
      const w = this.readWord();
      if (!w) throw new Unanalyzable("here-doc without a delimiter");
      const raw = this.src.slice(start, this.i);
      const quoted = /['"\\]/.test(raw);
      const delim = plainText(w);
      const r = { op, fd, target: null, heredoc: { body: "", quoted, script: null }, delim } as Redirect & { delim: string };
      this.pendingHeredocs.push(r);
      return r;
    }
    if ((op === ">&" || op === "<&") && /^[0-9-]/.test(s[this.i] ?? "")) {
      while (/[0-9-]/.test(s[this.i] ?? "")) this.i++;
      return { op, fd, target: null };
    }
    const w = this.readWord();
    if (!w) throw new Unanalyzable("redirection without a target");
    return { op, fd, target: w };
  }

  /** Read one word. `assignment` enables tilde expansion after ':' as in assignments. */
  readWord(assignment = false): Word | null {
    const start = this.i;
    const parts: Part[] = [];
    let brace = false;
    let lit = "";
    const flush = () => { if (lit) { parts.push({ t: "lit", s: lit, quoted: false }); lit = ""; } };
    const s = this.src;
    // Tilde prefix.
    if (s[this.i] === "~") {
      let j = this.i + 1;
      while (j < s.length && !META.has(s[j] as string) && s[j] !== "/" && s[j] !== ":" && s[j] !== '"' && s[j] !== "'" && s[j] !== "$" && s[j] !== "\\") j++;
      parts.push({ t: "tilde", user: s.slice(this.i + 1, j) });
      this.i = j;
    }
    while (this.i < s.length) {
      const c = s[this.i] as string;
      if (META.has(c)) break;
      if (c === "\\") {
        const n = s[this.i + 1];
        if (n === undefined) throw new Unanalyzable("trailing backslash");
        if (n === "\n") { this.i += 2; continue; }
        lit += n;
        this.i += 2;
        continue;
      }
      if (c === "'") {
        const end = s.indexOf("'", this.i + 1);
        if (end < 0) throw new Unanalyzable("unterminated single quote");
        flush();
        parts.push({ t: "lit", s: s.slice(this.i + 1, end), quoted: true });
        this.i = end + 1;
        continue;
      }
      if (c === "$" && s[this.i + 1] === "'") {
        flush();
        const [text, end] = ansiC(s, this.i + 2);
        parts.push({ t: "lit", s: text, quoted: true });
        this.i = end;
        continue;
      }
      if (c === '"' || (c === "$" && s[this.i + 1] === '"')) {
        flush();
        this.i += c === "$" ? 2 : 1;
        this.doubleQuoted(parts);
        continue;
      }
      if (c === "$" || c === "`") {
        flush();
        this.dollarOrBacktick(parts, false);
        continue;
      }
      if (c === "*" || c === "?" || (c === "[" && bracketClose(s, this.i) > 0)) {
        flush();
        if (c === "[") {
          const end = bracketClose(s, this.i);
          parts.push({ t: "glob", s: s.slice(this.i, end + 1) });
          this.i = end + 1;
        } else {
          parts.push({ t: "glob", s: c });
          this.i++;
        }
        continue;
      }
      if (c === "{") {
        const close = findBraceClose(s, this.i);
        if (close > 0) {
          const inner = s.slice(this.i + 1, close);
          if (inner.includes(",") || /^[^.]*\.\.[^.]*$/.test(inner)) brace = true;
        }
      }
      if (assignment && c === ":" && s[this.i + 1] === "~") {
        lit += ":";
        flush();
        this.i++;
        let j = this.i + 1;
        while (j < s.length && !META.has(s[j] as string) && s[j] !== "/" && s[j] !== ":") j++;
        parts.push({ t: "tilde", user: s.slice(this.i + 1, j) });
        this.i = j;
        continue;
      }
      lit += c;
      this.i++;
    }
    flush();
    if (this.i === start) return null;
    return { parts, raw: s.slice(start, this.i), brace };
  }

  private doubleQuoted(parts: Part[]): void {
    const s = this.src;
    let lit = "";
    const flush = () => { if (lit) { parts.push({ t: "lit", s: lit, quoted: true }); lit = ""; } };
    let sawAny = false;
    for (;;) {
      if (this.i >= s.length) throw new Unanalyzable("unterminated double quote");
      const c = s[this.i] as string;
      if (c === '"') { this.i++; break; }
      if (c === "\\") {
        const n = s[this.i + 1];
        if (n === "$" || n === "`" || n === '"' || n === "\\") { lit += n; this.i += 2; continue; }
        if (n === "\n") { this.i += 2; continue; }
        lit += "\\";
        this.i++;
        continue;
      }
      if (c === "$" || c === "`") {
        if (c === "$" && !isNameStart(s[this.i + 1]) && !"{(0123456789@*#?$!-".includes(s[this.i + 1] ?? "x")) { lit += c; this.i++; continue; }
        flush();
        sawAny = true;
        this.dollarOrBacktick(parts, true);
        continue;
      }
      lit += c;
      this.i++;
    }
    if (lit || !sawAny) parts.push({ t: "lit", s: lit, quoted: true });
    else flush();
  }

  private dollarOrBacktick(parts: Part[], quoted: boolean): void {
    const s = this.src;
    if (s[this.i] === "`") {
      // Find the closing unescaped backtick; unescape \` \\ \$ inside.
      let j = this.i + 1;
      let inner = "";
      while (j < s.length && s[j] !== "`") {
        if (s[j] === "\\" && (s[j + 1] === "`" || s[j + 1] === "\\" || s[j + 1] === "$")) { inner += s[j + 1]; j += 2; continue; }
        inner += s[j];
        j++;
      }
      if (j >= s.length) throw new Unanalyzable("unterminated backtick");
      this.i = j + 1;
      const p = new Parser(inner, this.depth + 1);
      const script = p.parseScript(null);
      parts.push({ t: "subst", script, quoted });
      return;
    }
    // s[i] === "$"
    const n = s[this.i + 1];
    if (n === "(" && s[this.i + 2] === "(") {
      const end = findArithClose(s, this.i + 3);
      if (end < 0) throw new Unanalyzable("unterminated $(( ))");
      const raw = s.slice(this.i + 3, end);
      if (raw.includes("$(") || raw.includes("`") || raw.includes("[")) throw new Unanalyzable("command inside arithmetic");
      if (!validArithmetic(raw)) throw new Unanalyzable("arithmetic expression the parser doesn't understand");
      parts.push({ t: "arith", raw });
      this.i = end + 2;
      return;
    }
    if (n === "(") {
      const p = new Parser(s, this.depth + 1);
      p.i = this.i + 2;
      p.tokens = this.tokens;
      const script = p.parseScript(")");
      if (p.peek() !== ")") throw new Unanalyzable("unterminated $( )");
      this.i = p.i + 1;
      this.tokens = p.tokens;
      parts.push({ t: "subst", script, quoted });
      return;
    }
    if (n === "{") {
      const end = findBraceClose(s, this.i + 1);
      if (end < 0) throw new Unanalyzable("unterminated ${ }");
      const inner = s.slice(this.i + 2, end);
      if (inner.includes("$(") || inner.includes("`")) throw new Unanalyzable("substitution inside ${ }");
      const m = /^[#!]?([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])/.exec(inner);
      if (!m) throw new Unanalyzable("unsupported ${ } form");
      parts.push({ t: "var", name: inner, braced: true, quoted });
      this.i = end + 1;
      return;
    }
    if (isNameStart(n)) {
      let j = this.i + 1;
      while (isNameChar(s[j])) j++;
      parts.push({ t: "var", name: s.slice(this.i + 1, j), braced: false, quoted });
      this.i = j;
      return;
    }
    if (n !== undefined && "0123456789@*#?$!-".includes(n)) {
      parts.push({ t: "var", name: n, braced: false, quoted });
      this.i += 2;
      return;
    }
    // A lone "$" is literal.
    parts.push({ t: "lit", s: "$", quoted });
    this.i += 1;
  }
}

/**
 * A conservative check that $(( … )) holds a plain arithmetic expression: numbers,
 * names, $vars, operators and parentheses, with no two operands in a row (T-DIFF found
 * `$(( X=1 cp *.log ))`, which bash rejects but a looser check accepted).
 */
function validArithmetic(raw: string): boolean {
  let i = 0;
  let expectOperand = true;
  let depth = 0;
  const ops = ["<<=", ">>=", "**", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "+", "-", "*", "/", "%", "<", ">", "=", "&", "|", "^", "!", "~", "?", ":", ","];
  while (i < raw.length) {
    const c = raw[i] as string;
    if (c === " " || c === "\t" || c === "\n") { i++; continue; }
    if (c === "(") { if (!expectOperand) return false; depth++; i++; continue; }
    if (c === ")") { if (expectOperand || depth === 0) return false; depth--; i++; continue; }
    const m = /^(\$\{[^}]*\}|\$?[A-Za-z_][A-Za-z0-9_]*|\$[0-9#?@*$!-]|[0-9][0-9A-Za-z#@_]*)/.exec(raw.slice(i, i + 200));
    if (m) {
      if (!expectOperand) return false;
      expectOperand = false;
      i += m[0].length;
      continue;
    }
    const op = ops.find((o) => raw.startsWith(o, i));
    if (!op) return false;
    if (op === "++" || op === "--" || op === "!" || op === "~") { i += op.length; continue; }
    if ((op === "+" || op === "-") && expectOperand) { i++; continue; }
    if (expectOperand) return false;
    expectOperand = true;
    i += op.length;
  }
  return !expectOperand && depth === 0 || raw.trim() === "";
}

/** Index of the `]` closing a glob bracket expression within the same word, or -1. */
function bracketClose(s: string, open: number): number {
  for (let j = open + 1; j < s.length && j < open + 256; j++) {
    const c = s[j] as string;
    if (META.has(c) || c === "'" || c === '"') return -1;
    if (c === "]" && j > open + 1) return j;
  }
  return -1;
}

function before(script: Script, s: Script): number {
  return script.commands.length - s.commands.length;
}

function findBraceClose(s: string, open: number): number {
  let depth = 0;
  for (let j = open; j < s.length && j < open + 4096; j++) {
    const c = s[j];
    if (c === "\\") { j++; continue; }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return j; }
    else if (c === " " || c === "\n" || c === "\t" || c === ";" || c === "|" || c === "&") { if (s[open - 1] !== "$") return -1; }
  }
  return -1;
}

function findArithClose(s: string, from: number): number {
  let depth = 0;
  for (let j = from; j < s.length - 1; j++) {
    if (s[j] === "(") depth++;
    else if (s[j] === ")") {
      if (depth === 0 && s[j + 1] === ")") return j;
      depth--;
    }
  }
  return -1;
}

/** Decode $'…' (ANSI-C quoting). Returns [text, index after closing quote]. */
function ansiC(s: string, from: number): [string, number] {
  let out = "";
  let j = from;
  while (j < s.length) {
    const c = s[j] as string;
    if (c === "'") return [out, j + 1];
    if (c !== "\\") { out += c; j++; continue; }
    const n = s[j + 1];
    j += 2;
    switch (n) {
      case "n": out += "\n"; break;
      case "t": out += "\t"; break;
      case "r": out += "\r"; break;
      case "a": out += "\x07"; break;
      case "b": out += "\b"; break;
      case "e": case "E": out += "\x1b"; break;
      case "f": out += "\f"; break;
      case "v": out += "\v"; break;
      case "\\": out += "\\"; break;
      case "'": out += "'"; break;
      case '"': out += '"'; break;
      case "?": out += "?"; break;
      case "c": throw new Unanalyzable("$'\\c' control escapes are not supported");
      case "x": {
        const m = /^[0-9a-fA-F]{1,2}/.exec(s.slice(j, j + 2));
        if (!m) { out += "\\x"; break; }
        out += String.fromCharCode(parseInt(m[0], 16));
        j += m[0].length;
        break;
      }
      case "u": case "U": {
        const m = (n === "u" ? /^[0-9a-fA-F]{1,4}/ : /^[0-9a-fA-F]{1,8}/).exec(s.slice(j, j + (n === "u" ? 4 : 8)));
        if (!m) { out += "\\" + n; break; }
        const cp = parseInt(m[0], 16);
        if (cp > 0x10ffff) throw new Unanalyzable("bad \\U escape");
        out += String.fromCodePoint(cp);
        j += m[0].length;
        break;
      }
      default: {
        if (n !== undefined && n >= "0" && n <= "7") {
          const m = /^[0-7]{1,3}/.exec(s.slice(j - 1, j + 2)) as RegExpExecArray;
          out += String.fromCharCode(parseInt(m[0], 8) & 0xff);
          j += m[0].length - 1;
          break;
        }
        if (n === undefined) throw new Unanalyzable("unterminated $'");
        out += "\\" + n;
      }
    }
  }
  throw new Unanalyzable("unterminated $'");
}

/** Command substitutions inside an unquoted here-doc body are real. Parse them. */
function expansionsOfHeredoc(body: string, depth: number): Script | null {
  if (!body.includes("$(") && !body.includes("`")) return null;
  const script: Script = { commands: [], functions: [] };
  let i = 0;
  while (i < body.length) {
    const c = body[i];
    if (c === "\\") { i += 2; continue; }
    if (c === "$" && body[i + 1] === "(" && body[i + 2] !== "(") {
      const p = new Parser(body, depth + 1);
      p.i = i + 2;
      const inner = p.parseScript(")");
      if (body[p.i] !== ")") throw new Unanalyzable("unterminated $( ) in here-doc");
      script.commands.push(...inner.commands);
      i = p.i + 1;
      continue;
    }
    if (c === "$" && body[i + 1] === "(" && body[i + 2] === "(") {
      const end = findArithClose(body, i + 3);
      if (end < 0) throw new Unanalyzable("unterminated $(( )) in here-doc");
      if (body.slice(i, end).includes("$(") || body.slice(i, end).includes("`")) throw new Unanalyzable("command inside arithmetic");
      i = end + 2;
      continue;
    }
    if (c === "`") {
      let j = i + 1;
      let inner = "";
      while (j < body.length && body[j] !== "`") {
        if (body[j] === "\\" && (body[j + 1] === "`" || body[j + 1] === "\\" || body[j + 1] === "$")) { inner += body[j + 1]; j += 2; continue; }
        inner += body[j];
        j++;
      }
      if (j >= body.length) throw new Unanalyzable("unterminated backtick in here-doc");
      script.commands.push(...new Parser(inner, depth + 1).parseScript(null).commands);
      i = j + 1;
      continue;
    }
    i++;
  }
  return script;
}

export function litWord(s: string): Word {
  return { parts: [{ t: "lit", s, quoted: false }], raw: s, brace: false };
}

/** Text of a word whose parts are all literal; otherwise the raw text. */
export function plainText(w: Word): string {
  return w.parts.every((p) => p.t === "lit") ? w.parts.map((p) => (p as { s: string }).s).join("") : w.raw;
}

function isPlainName(w: Word): boolean {
  return w.parts.length === 1 && w.parts[0]?.t === "lit" && !w.parts[0].quoted && isPlainNameStr(w.parts[0].s);
}

function isPlainNameStr(s: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_.:-]*$/.test(s);
}
