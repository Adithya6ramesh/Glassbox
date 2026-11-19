// The public-source benchmark corpus (bench/public, bench/SOURCES.md) holds real attack
// commands as inert data. T-DIFF executes commands in bash, so it must only ever run its own
// fixed corpus: no file in this package may refer to the benchmark's data.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const PKG = new URL("../", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    if (n === "node_modules" || n === "dist") return [];
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : [p];
  });
}

describe("T-DIFF never touches the public benchmark corpus", () => {
  it("no source or test in shell-difftest mentions bench/ data", () => {
    const hits = files(PKG)
      .filter((f) => !f.endsWith("inert-corpus.test.ts"))
      .filter((f) => /bench[\\/]|public[\\/](dev|holdout)\.json|dev\.json|holdout\.json/.test(readFileSync(f, "utf8")));
    expect(hits).toEqual([]);
  });

  it("the corpus T-DIFF runs is its own module", () => {
    const harness = readFileSync(join(PKG, "src", "harness.ts"), "utf8");
    expect(harness).not.toMatch(/readFileSync\([^)]*json/);
  });
});
