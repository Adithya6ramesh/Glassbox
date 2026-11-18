// T-DIFF support (engine-spec §13): the parser's view of which commands a shell string
// runs, as argv lists. Unknown words are null (they match zero or more real words).
import { analyzeShellCommand, wordInfo } from "./analyze.js";
import { parseShell, type Part, type Script, type SimpleCommand, type Word } from "./parse.js";

export interface ShellView {
  analyzable: boolean;
  commands: (string | null)[][];
}

const VIEW_CTX = {
  pctx: { platform: "linux" as const, homeDir: "/home/u", cwd: "/home/u/proj", caseInsensitive: false, glassboxDirs: ["/home/u/.glassbox"], extraProtected: [], extraSensitive: [], secretPaths: [] },
  depth: 0,
  maxBytes: 16 * 1024,
};

function expandBrace(w: Word): string[] | null {
  if (!w.parts.every((p) => p.t === "lit")) return null;
  const s = w.parts.map((p) => (p as { s: string }).s).join("");
  const raw = w.raw;
  const open = raw.indexOf("{");
  const close = raw.indexOf("}", open);
  if (open < 0 || close < 0 || raw.slice(open + 1).indexOf("{") >= 0 && raw.slice(open + 1).indexOf("{") < close - open - 1) return null;
  const inner = raw.slice(open + 1, close);
  if (!inner.includes(",") || inner.includes("..") || /['"$`]/.test(raw)) return null;
  const alts = inner.split(",");
  if (alts.some((a) => a === "")) return null;
  const pre = raw.slice(0, open);
  const post = raw.slice(close + 1);
  if (post.includes("{")) return null;
  void s;
  return alts.map((a) => pre + a + post);
}

function argvOf(c: SimpleCommand): (string | null)[] {
  const out: (string | null)[] = [];
  for (const w of c.words) {
    if (w.brace) {
      const e = expandBrace(w);
      if (e) { out.push(...e); continue; }
      out.push(null);
      continue;
    }
    const info = wordInfo(w);
    out.push(info.dynamic || info.glob || hasEqTilde(w) ? null : info.value);
  }
  return out;
}

function hasEqTilde(w: Word): boolean {
  return w.parts.some((p) => p.t === "lit" && !p.quoted && /=~|:~/.test(p.s));
}

function collect(script: Script, out: (string | null)[][]): void {
  for (const c of script.commands) {
    const argv = argvOf(c);
    if (argv.length > 0) {
      out.push(argv);
      // `command x`, `builtin x`, `exec x`: bash runs x itself.
      let k = 0;
      while (["command", "builtin", "exec", "time"].includes(argv[k] ?? "") && k < 3) {
        k++;
        while ((argv[k] ?? "").startsWith("-") && k < argv.length) k++;
        if (k < argv.length) out.push(argv.slice(k));
      }
    }
    const words: Word[] = [...c.words, ...c.assigns.flatMap((a) => (a.value ? [a.value] : [])), ...c.redirects.flatMap((r) => (r.target ? [r.target] : []))];
    for (const w of words) for (const p of w.parts as Part[]) if (p.t === "subst") collect(p.script, out);
    for (const r of c.redirects) if (r.heredoc?.script) collect(r.heredoc.script, out);
  }
}

export function shellArgvView(src: string): ShellView {
  try {
    const script = parseShell(src, { maxBytes: VIEW_CTX.maxBytes });
    const acc = analyzeShellCommand(src, VIEW_CTX);
    const commands: (string | null)[][] = [];
    collect(script, commands);
    return { analyzable: !acc.unanalyzableFlag, commands };
  } catch {
    return { analyzable: false, commands: [] };
  }
}
