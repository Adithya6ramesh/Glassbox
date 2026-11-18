// T-DIFF (spec §13): the engine's shell parser vs. real bash.
// A case fails when the parser says "analyzable" but bash executed a command the parser
// didn't list (or bash rejected the syntax). "Unanalyzable" never fails: it's the safe answer.
// Runs on Linux/macOS (/bin/bash) or wherever GLASSBOX_BASH points (e.g. Git Bash on Windows).
import { describe, expect, it } from "vitest";
import { shellArgvView } from "../../engine/src/action/shell/view.js";
import { buildCorpus } from "../src/corpus.js";
import { findBash, runInBash, viewCovers } from "../src/harness.js";

const bash = findBash();
const CONCURRENCY = 8;

describe.runIf(bash !== undefined)("T-DIFF: shell parser vs real bash", () => {
  it("harness sanity: bash runs and the logger records externals and echo", async () => {
    const r = await runInBash(bash!, "rm -rf / ; echo 'a b' $'c\\x41'");
    expect(r.executed).toEqual([["rm", "-rf", "/"], ["echo", "a b", "cA"]]);
  });

  it("matcher: null parser words match zero or more words", () => {
    expect(viewCovers([["echo", null, "x"]], ["echo", "x"])).toBe(true);
    expect(viewCovers([["echo", null, "x"]], ["echo", "a", "b", "x"])).toBe(true);
    expect(viewCovers([["echo", "x"]], ["echo", "y"])).toBe(false);
  });

  it("corpus has ≥ 2,000 commands", () => {
    expect(buildCorpus().length).toBeGreaterThanOrEqual(2000);
  });

  it("every command bash executes is in the parser's view when the parser says analyzable", async () => {
    const corpus = buildCorpus();
    const failures: string[] = [];
    let analyzable = 0;
    let next = 0;
    async function worker() {
      while (next < corpus.length) {
        const cmd = corpus[next++]!;
        const view = shellArgvView(cmd);
        if (!view.analyzable) continue;
        analyzable++;
        const run = await runInBash(bash!, cmd);
        if (run.syntaxError) { failures.push(`bash rejects, parser accepts: ${JSON.stringify(cmd)}`); continue; }
        for (const argv of run.executed) {
          if (!viewCovers(view.commands, argv)) {
            failures.push(`missed ${JSON.stringify(argv)} in ${JSON.stringify(cmd)}; parser saw ${JSON.stringify(view.commands)}`);
            break;
          }
        }
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    console.log(`[T-DIFF] ${corpus.length} commands, ${analyzable} analyzable, ${failures.length} failures`);
    expect(failures.slice(0, 25)).toEqual([]);
  }, 1_800_000);
});
