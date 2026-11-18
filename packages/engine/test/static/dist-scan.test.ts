// I7, build half: the compiled engine (dist/) contains no banned modules or constructs.
// The lint half is banned-code.test.ts. Runs after `tsc -b` (pnpm run check builds first).
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const dist = fileURLToPath(new URL("../../dist/", import.meta.url));

function* walk(dir: string): Generator<string> {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (p.endsWith(".js")) yield p;
  }
}

describe("I7: compiled engine output", () => {
  it("dist exists (build ran first)", () => {
    expect(existsSync(join(dist, "index.js"))).toBe(true);
  });

  it("imports only relative modules and the 4 reviewed dependencies", () => {
    const allowed = /^(\.{1,2}\/|re2js$|valibot$|@noble\/hashes\/|@noble\/curves\/)/;
    for (const f of walk(dist)) {
      const src = readFileSync(f, "utf8");
      for (const m of src.matchAll(/(?:^|\n)\s*(?:import|export)\b[^'"]*?from\s*["']([^"']+)["']|(?:^|\n)\s*import\s*["']([^"']+)["']/g)) {
        const spec = m[1] ?? m[2] ?? "";
        expect(spec, `${f}: ${spec}`).toMatch(allowed);
      }
      expect(src, f).not.toMatch(/\bimport\s*\(/);
      expect(src, f).not.toMatch(/(?<![.\w$])(eval|Function)\s*\(|new\s+Function\b|\brequire\s*\(/);
      expect(src, f).not.toMatch(/\bprocess\.|\bglobalThis\b|\bDate\.now\b|\bMath\.random\b/);
    }
  });
});
