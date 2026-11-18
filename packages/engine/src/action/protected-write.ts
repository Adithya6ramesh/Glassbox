// Write targets that reach protected paths indirectly (red team, Phase 0 Step 4):
// - an ancestor directory (moving or deleting ~/.claude moves its settings and hooks)
// - a glob that could match a protected file or a path inside a protected directory
import { ANYWHERE, entries, fold, isProtected, isProtectedRead, normalizeFull, readProtectedEntries, type NormPath, type PathCtx } from "./paths.js";

interface Cand { p: string; dir: boolean; project: boolean }

/** Concrete protected paths a write could hit. `project` marks the cwd's "anywhere" files. */
function candidates(ctx: PathCtx): Cand[] {
  const out: Cand[] = entries(ctx).map((e) => ({ p: e.p, dir: e.dir, project: false }));
  for (const e of readProtectedEntries(ctx)) out.push({ p: e.p.endsWith("/*.key") ? e.p.slice(0, -6) : e.p, dir: e.p.endsWith("/*.key"), project: false });
  if (ctx.cwd !== null) {
    const cwd = normalizeFull(ctx.cwd, ctx);
    if (cwd) for (const a of ANYWHERE) out.push({ p: cwd + fold(a, ctx.caseInsensitive), dir: false, project: true });
  }
  return out;
}

/** Shell-style glob match of one path segment. `*` and `?` don't match a leading dot. */
export function segMatch(pat: string, s: string): boolean {
  if (s.startsWith(".") && !pat.startsWith(".")) return false;
  let p = 0, i = 0, star = -1, mark = 0;
  while (i < s.length) {
    const pc = pat[p];
    const sc = s[i] as string;
    if (pc === "[") {
      const close = pat.indexOf("]", p + 1);
      if (close > p) {
        const set = pat.slice(p + 1, close);
        const neg = set.startsWith("!") || set.startsWith("^");
        const body = neg ? set.slice(1) : set;
        let hit = false;
        for (let k = 0; k < body.length; k++) {
          const lo = body[k] as string;
          const hi = body[k + 2];
          if (body[k + 1] === "-" && hi !== undefined) { if (sc >= lo && sc <= hi) hit = true; k += 2; }
          else if (lo === sc) hit = true;
        }
        if (hit !== neg) { p = close + 1; i++; continue; }
      }
    } else if (pc === "?" || (pc !== undefined && pc !== "*" && pc === sc)) { p++; i++; continue; }
    if (pc === "*") { star = p++; mark = i; continue; }
    if (star >= 0) { p = star + 1; i = ++mark; continue; }
    return false;
  }
  while (pat[p] === "*") p++;
  return p === pat.length;
}

function segsMatch(ps: string[], xs: string[]): boolean {
  return ps.length === xs.length && ps.every((seg, k) => segMatch(seg, xs[k] as string));
}

/**
 * Is `np` (written, moved, deleted, chmod-ed or linked) a protected path, an ancestor
 * directory of one, or a glob pattern that could match one?
 * Project-level files (<cwd>/.mcp.json, <cwd>/.claude/settings*.json) count for ancestors
 * only strictly inside the project, so `chmod -R u+w .` on the project root stays allowed.
 */
export function isProtectedWrite(np: NormPath, ctx: PathCtx, isGlob = false): boolean {
  if (isProtected(np, ctx) || isProtectedRead(np, ctx)) return true;
  if (np.path === null) return false;
  const p = np.path.replace(/\/+$/, "");
  if (p.length === 0) return false;
  const cwd = ctx.cwd !== null ? normalizeFull(ctx.cwd, ctx) : null;
  const insideProject = cwd !== null && p.startsWith(cwd + "/");
  const cands = candidates(ctx);
  if (cands.some((c) => c.p.startsWith(p + "/") && (!c.project || insideProject))) return true;
  if (!isGlob) return false;
  const ps = p.split("/");
  for (const c of cands) {
    const cs = c.p.split("/");
    // The pattern names the candidate or one of its ancestors…
    for (let n = cs.length; n > 1; n--) {
      if (n === cs.length || !c.project || ps.length > (cwd?.split("/").length ?? 0)) {
        if (segsMatch(ps, cs.slice(0, n))) return true;
      }
    }
    // …or a path inside a protected directory.
    if (c.dir && ps.length > cs.length && segsMatch(ps.slice(0, cs.length), cs)) return true;
  }
  return false;
}
