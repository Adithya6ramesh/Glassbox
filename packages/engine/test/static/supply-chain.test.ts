// Supply-chain guards (Phase 0 locked decisions: ignore-scripts, few pinned deps,
// no eval in the engine or its runtime dependencies). Red team, Phase 0 Step 2.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const engineDir = fileURLToPath(new URL("../../", import.meta.url));
const repoRoot = join(engineDir, "../..");
const enginePkg = JSON.parse(readFileSync(join(engineDir, "package.json"), "utf8")) as {
  dependencies?: Record<string, string>;
  scripts?: Record<string, string>;
};

// Adding a runtime dependency needs a reviewed reason: exact version, at least 14 days old, no install scripts.
const ALLOWED_RUNTIME_DEPS = ["@noble/curves", "@noble/hashes", "re2js", "valibot"];
const INSTALL_HOOKS = ["preinstall", "install", "postinstall", "prepare"];

describe("engine runtime dependencies", () => {
  it("RT-S3: only the reviewed runtime dependencies are declared", () => {
    expect(Object.keys(enginePkg.dependencies ?? {}).sort()).toEqual(ALLOWED_RUNTIME_DEPS);
  });

  it("RT-S4: every dependency in the workspace is pinned to an exact version", () => {
    const manifests = [
      join(repoRoot, "package.json"),
      ...readdirSync(join(repoRoot, "packages")).map((d) => join(repoRoot, "packages", d, "package.json")),
    ];
    for (const file of manifests) {
      const pkg = JSON.parse(readFileSync(file, "utf8")) as Record<string, Record<string, string> | undefined>;
      for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
        for (const [name, range] of Object.entries(pkg[field] ?? {})) {
          expect(range, `${file} ${field} ${name}`).toMatch(/^(\d+\.\d+\.\d+|workspace:\*)$/);
        }
      }
    }
  });

  it("RT-S5: no runtime dependency, and not the engine, has install-time scripts", () => {
    const req = createRequire(join(engineDir, "package.json"));
    for (const dep of ALLOWED_RUNTIME_DEPS) {
      const pkgJson = findPackageJson(dirname(req.resolve(dep)), dep);
      const scripts = (JSON.parse(readFileSync(pkgJson, "utf8")) as { scripts?: Record<string, string> }).scripts ?? {};
      for (const hook of INSTALL_HOOKS) expect(scripts[hook], `${dep} ${hook}`).toBeUndefined();
    }
    for (const hook of INSTALL_HOOKS) expect(enginePkg.scripts?.[hook]).toBeUndefined();
  });

  it("RT-S6: runtime dependency code contains no eval, Function constructor or host I/O", () => {
    const req = createRequire(join(engineDir, "package.json"));
    let scanned = 0;
    for (const dep of ALLOWED_RUNTIME_DEPS) {
      const root = dirname(findPackageJson(dirname(req.resolve(dep)), dep));
      for (const file of walk(root)) {
        if (!/\.(c|m)?js$/.test(file)) continue;
        scanned++;
        expect(scanForBannedCode(readFileSync(file, "utf8")), `${dep}: ${file}`).toEqual([]);
      }
    }
    expect(scanned).toBeGreaterThan(0);
  });

  // Positive control. RT-S8: the first version of the scanner missed zod 4's
  // `const F = Function;` alias, so these known-bad forms must keep being caught.
  it.each([
    ["Function alias (zod 4 style)", "const F = Function;\nreturn new F(code);"],
    ["new Function", "const f = new Function('a', 'return a');"],
    ["Function call", "const f = Function('return this')();"],
    ["bare eval call", "const v = eval(src);"],
    ["indirect eval", "const v = (0, eval)(src);"],
    ["eval alias", "const e = eval;"],
    ["eval through a ternary", "const e = ok ? eval : noop;"],
    ["child_process", "const cp = require('child_process');"],
    ["require fs", "const fs = require(\"node:fs\");"],
  ])("RT-S8: the dependency scanner flags %s", (_name, code) => {
    expect(scanForBannedCode(code).length).toBeGreaterThan(0);
  });

  it.each([
    ["method call named eval", "if (!this.prefilter.eval(input, pos)) return null;"],
    ["method definition named eval", "  eval(a, x, brp = false) {\n    return a;\n  }"],
    ["object key named eval", "const p = {\n  eval: (a, basis) => a,\n};"],
    ["comment", "  // Same as eval(a, basis), but faster"],
    ["Function.prototype", "const call = Function.prototype.call;"],
    ["string mention", "throw new TypeError('expected \"Function\"');"],
  ])("RT-S8: the dependency scanner allows %s", (_name, code) => {
    expect(scanForBannedCode(code)).toEqual([]);
  });
});

/** Returns the banned constructs found in a dependency's JavaScript source. */
function scanForBannedCode(src: string): string[] {
  const banned =
    /(?<![.\w$'"`])eval(?![\w$])|(?<![.\w$'"`])Function(?![\w$])(?!\s*\.\s*prototype)|child_process|require\(\s*["'](node:)?(fs|net|http|https|vm)["']\s*\)/g;
  return [...src.matchAll(banned)]
    // A method *definition* named eval (`eval(a, x) {`, noble's polynomial helpers)
    // isn't a call to the global eval.
    .filter((m) => !(m[0] === "eval" && /^eval\s*\([^()]*\)\s*\{/.test(src.slice(m.index))))
    // An object key named eval (`{ eval: (a) => … }`) isn't the global either. A ternary
    // (`c ? eval : x`) is, so the key form needs `{`, `,` or a line start before it.
    .filter((m) => !(m[0] === "eval" && /^eval\s*:/.test(src.slice(m.index)) &&
      /(^|[{,])\s*$/.test(src.slice(src.lastIndexOf("\n", m.index) + 1, m.index))))
    // Text after `//` on the same line, or on a `*` doc-comment line, is a comment.
    .filter((m) => {
      const prefix = src.slice(src.lastIndexOf("\n", m.index) + 1, m.index);
      return !(prefix.includes("//") || /^\s*\*/.test(prefix));
    })
    .map((m) => m[0]);
}

describe("workspace install settings", () => {
  const ws = readFileSync(join(repoRoot, "pnpm-workspace.yaml"), "utf8");
  const lines = ws.split(/\r?\n/);

  it("RT-S9: ignoreScripts is not enabled (it would silently skip the strictDepBuilds check)", () => {
    expect(ws).not.toMatch(/^\s*ignoreScripts\s*:\s*true/m);
  });

  it("RT-S9: no workspace package declares install-time lifecycle scripts", () => {
    const manifests = [
      join(repoRoot, "package.json"),
      ...readdirSync(join(repoRoot, "packages")).map((d) => join(repoRoot, "packages", d, "package.json")),
    ];
    for (const file of manifests) {
      const scripts = (JSON.parse(readFileSync(file, "utf8")) as { scripts?: Record<string, string> }).scripts ?? {};
      for (const hook of INSTALL_HOOKS) expect(scripts[hook], `${file} ${hook}`).toBeUndefined();
    }
  });

  it.each([
    ["strictDepBuilds: true"],
    ["dangerouslyAllowAllBuilds: false"],
    ["blockExoticSubdeps: true"],
    ["trustPolicy: no-downgrade"],
    ["minimumReleaseAgeStrict: true"],
  ])("RT-S7: pnpm-workspace.yaml keeps `%s`", (line) => {
    expect(lines).toContain(line);
  });

  it("RT-S7: no package is allowed to run build scripts", () => {
    expect(ws).not.toMatch(/^\s*allowBuilds\s*:/m);
    expect(ws).not.toMatch(/^\s*permissions\s*:/m);
  });

  it("RT-S7: minimum release age is at least 14 days", () => {
    const m = /^minimumReleaseAge:\s*(\d+)\s*$/m.exec(ws);
    expect(Number(m?.[1])).toBeGreaterThanOrEqual(14 * 24 * 60);
  });
});

function findPackageJson(start: string, name: string): string {
  let dir = start;
  for (let i = 0; i < 10; i++) {
    const candidate = join(dir, "package.json");
    try {
      if ((JSON.parse(readFileSync(candidate, "utf8")) as { name?: string }).name === name) return candidate;
    } catch {
      // not here; keep walking up
    }
    dir = dirname(dir);
  }
  throw new Error(`package.json for ${name} not found`);
}

function* walk(dir: string): Generator<string> {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}
