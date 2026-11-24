// Invariant I7, lint half: banned modules, globals and syntax in
// packages/engine/src are rejected. Each case is a red-team attempt (Phase 0 Step 2).
import { ESLint } from "eslint";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../../", import.meta.url));
const eslint = new ESLint({ cwd: repoRoot });
const ENGINE_FILE = "packages/engine/src/__probe__.ts";

async function errorsFor(code: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: ENGINE_FILE });
  return (result?.messages ?? []).filter((m) => m.severity === 2).map((m) => m.ruleId ?? "fatal");
}

const MUST_FAIL: ReadonlyArray<readonly [string, string]> = [
  ["static node:fs import", `import { readFileSync } from "node:fs"; export const x = readFileSync;`],
  ["bare fs import", `import fs from "fs"; export const x = fs;`],
  ["child_process", `import { spawn } from "node:child_process"; export const x = spawn;`],
  ["vm", `import vm from "node:vm"; export const x = vm;`],
  ["os (host-specific)", `import os from "node:os"; export const x = os;`],
  ["path (platform-specific)", `import path from "node:path"; export const x = path;`],
  ["re-export from a banned module", `export { readFileSync } from "node:fs";`],
  ["dynamic import", `export const x = () => import("./other.js");`],
  ["eval", `export const x = (s: string) => eval(s);`],
  ["indirect eval", `export const x = (s: string) => (0, eval)(s);`],
  ["new Function", `export const x = new Function("return 1");`],
  ["Function()", `export const x = Function("return 1");`],
  ["RT-S2 constructor route to Function", `export const x = (() => 0).constructor("return 1");`],
  ["RT-S2 computed constructor", `export const x = (() => 0)["constructor"];`],
  ["RegExp constructor", `export const x = (p: string) => new RegExp(p);`],
  ["process.env", `export const x = process.env;`],
  ["require", `export const x = require("fs");`],
  ["Buffer", `export const x = Buffer.from("a");`],
  ["fetch", `export const x = () => fetch("https://example.invalid");`],
  ["globalThis lookup of eval", `export const x = globalThis["ev" + "al"];`],
  ["timers", `setTimeout(() => 0, 1);`],
  ["Math.random", `export const x = Math.random();`],
  ["Date.now", `export const x = Date.now();`],
  ["new Date()", `export const x = new Date();`],
  ["Reflect", `export const x = Reflect.get({}, "a");`],
  ["__proto__", `export const x = ({} as { __proto__: unknown }).__proto__;`],
];

describe("engine source: banned code is rejected by lint (I7)", () => {
  it.each(MUST_FAIL)("%s", async (_name, code) => {
    expect((await errorsFor(code)).length).toBeGreaterThan(0);
  });

  it("RT-S1: an inline eslint-disable-next-line comment does not switch the ban off", async () => {
    const code = "// eslint-disable-next-line\nexport const x = (s: string) => eval(s);";
    expect(await errorsFor(code)).toContain("no-eval");
  });

  it("RT-S1: a file-wide eslint-disable comment does not switch the ban off", async () => {
    const code = '/* eslint-disable */\nimport fs from "node:fs";\nexport const x = fs;';
    expect(await errorsFor(code)).toContain("no-restricted-imports");
  });

  it("allows ordinary pure code, regex literals and performance.now()", async () => {
    const code = "export const f = (s: string): boolean => /^[a-z]+$/.test(s) && performance.now() >= 0;";
    expect(await errorsFor(code)).toEqual([]);
  });
});
