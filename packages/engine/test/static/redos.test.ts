// Engine-internal regex literals must be ReDoS-safe (engine-spec §10.3). Rule regexes run
// on re2js (linear time); the engine's own JS regex literals run on V8's backtracking
// engine, so each one is checked with recheck and must come back "safe".
// (Gap found in the Step 6 follow-up: the spec required this check but nothing ran it.)
import { readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const { checkSync } = require("recheck") as { checkSync: (src: string, flags: string, opts?: { timeout?: number }) => { status: string; attack?: { pattern?: string } } };

const SRC = new URL("../../src/", import.meta.url);

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return files(p);
    return p.endsWith(".ts") && !p.endsWith(".generated.ts") ? [p] : [];
  });
}

function literals(): { where: string; source: string; flags: string }[] {
  const out: { where: string; source: string; flags: string }[] = [];
  for (const f of files(SRC.pathname.replace(/^\/([A-Za-z]:)/, "$1"))) {
    const text = readFileSync(f, "utf8");
    const sf = ts.createSourceFile(f, text, ts.ScriptTarget.Latest, true);
    const visit = (n: ts.Node) => {
      if (n.kind === ts.SyntaxKind.RegularExpressionLiteral) {
        const lit = n.getText(sf);
        const end = lit.lastIndexOf("/");
        const line = sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
        out.push({ where: `${f.slice(f.indexOf("src"))}:${line}`, source: lit.slice(1, end), flags: lit.slice(end + 1) });
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return out;
}

const ALL = literals();

describe("engine regex literals are ReDoS-safe (recheck)", () => {
  it("finds the engine's regex literals", () => {
    expect(ALL.length).toBeGreaterThan(20);
  });

  it("every literal is safe", () => {
    const unsafe: string[] = [];
    // Deduplicate identical patterns; recheck is slow-ish.
    const seen = new Map<string, string>();
    for (const r of ALL) {
      const key = `${r.flags}/${r.source}`;
      let status = seen.get(key);
      if (status === undefined) {
        status = checkSync(r.source, r.flags.replace(/[gy]/g, ""), { timeout: 10_000 }).status;
        seen.set(key, status);
      }
      if (status !== "safe") unsafe.push(`${r.where} /${r.source}/${r.flags} → ${status}`);
    }
    expect(unsafe).toEqual([]);
  }, 600_000);
});
