// Stress run: the full test suite N times, each with a fresh random seed.
// The seed shuffles test order (vitest --sequence.seed) and fixes fast-check's
// seed (vitest.seed.ts), so any failure replays exactly with:
//   pnpm run stress --runs 1 --seed <seed>
// Run through pnpm so npm_execpath points at pnpm (build-script-install.test.ts needs it).
import { spawnSync } from "node:child_process";
import { randomInt } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] !== undefined ? Number(args[i + 1]) : dflt;
};
const runs = opt("runs", 50);
const fixedSeed = opt("seed", undefined);
if (!Number.isSafeInteger(runs) || runs < 1) throw new Error("--runs must be a positive integer");

// vitest's CLI file isn't in its "exports"; find it through its package.json "bin".
const vitestPkg = createRequire(import.meta.url).resolve("vitest/package.json");
const bin = JSON.parse(readFileSync(vitestPkg, "utf8")).bin;
const vitest = join(dirname(vitestPkg), typeof bin === "string" ? bin : bin.vitest);
const failures = [];
const started = performance.now();

for (let n = 1; n <= runs; n++) {
  const seed = fixedSeed ?? randomInt(1, 2 ** 31 - 1);
  const t0 = performance.now();
  const r = spawnSync(process.execPath, [vitest, "run", "--sequence.shuffle", `--sequence.seed=${seed}`], {
    env: { ...process.env, GLASSBOX_TEST_SEED: String(seed), FORCE_COLOR: "0" },
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  const secs = ((performance.now() - t0) / 1000).toFixed(1);
  if (r.status === 0) {
    console.log(`run ${n}/${runs}  seed ${seed}  pass  ${secs}s`);
    continue;
  }
  const failed = [...new Set(out.split("\n").filter((l) => /^\s*FAIL\s/.test(l)).map((l) => l.trim()))];
  failures.push({ n, seed, failed });
  console.log(`run ${n}/${runs}  seed ${seed}  FAIL (exit ${r.status ?? r.signal})  ${secs}s`);
  for (const f of failed) console.log(`    ${f}`);
  console.log(out.split("\n").slice(-60).join("\n"));
}

const total = ((performance.now() - started) / 1000).toFixed(0);
const lines = [
  `## Stress: ${runs} runs, ${failures.length} failed (${total}s)`,
  "",
  ...(failures.length === 0
    ? ["Every run passed."]
    : ["| run | seed | failing tests | replay |", "|---|---|---|---|",
        ...failures.map((f) => `| ${f.n} | ${f.seed} | ${f.failed.join("<br>").replace(/\|/g, "\\|") || "(see log)"} | \`pnpm run stress --runs 1 --seed ${f.seed}\` |`)]),
];
console.log(`\n${lines.join("\n")}`);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${lines.join("\n")}\n`);
process.exit(failures.length === 0 ? 0 : 1);
