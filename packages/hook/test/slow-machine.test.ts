// A slow machine, simulated: the clock the engine and hook read (performance.now) runs N times
// faster than real time, so every check looks N times slower. The hook passes the engine
// 750 ms (PreToolUse) and 1,500 ms (PostToolUse) instead of the engine's 100 ms default.
// - Normal inputs (the T-CORPUS commands) on a slowed clock give the same verdicts as on a
//   normal clock: no false denies from the time limit.
// - Checks over 100 ms are recorded as slowCheck in the event.
// - Huge or pathological inputs still hit the limit (CP-LIMIT-010) and are treated as degraded.
import { afterEach, describe, expect, it, vi } from "vitest";
import { CORPUS } from "../../engine/test/corpus/claude-code-commands.js";
import { HARD_STOP_MS, runHook } from "../src/index.js";
import { bash, makeEnv, post, pre, spooled, toolUseId } from "./helpers.js";

function slowClock(factor: number): void {
  const real = performance.now.bind(performance);
  const t0 = real();
  vi.spyOn(performance, "now").mockImplementation(() => t0 + (real() - t0) * factor);
}
afterEach(() => vi.restoreAllMocks());

const decision = (stdout: string) => (stdout ? (JSON.parse(stdout) as { hookSpecificOutput?: { permissionDecision?: string } }).hookSpecificOutput?.permissionDecision ?? "none" : "none");

interface Check { decision: string; engineMs: number; slow: boolean; hitLimit: boolean }

/** One T-CORPUS command through the hook: its decision and what the event recorded. */
function check(i: number): Check {
  const env = makeEnv();
  const c = CORPUS[i]!;
  const payload = c.tool === "Bash" ? pre(env, "Bash", bash(c.command)) : pre(env, "PowerShell", { command: c.command });
  const d = decision(runHook("pre", JSON.stringify(payload), env).stdout);
  const e = spooled(env).find((x) => x.kind === "tool_pre")!;
  return { decision: d, engineMs: e.timing.engineMs, slow: e.timing.slowCheck === true, hitLimit: (e.degradedReasons ?? []).includes("CP-LIMIT-010") };
}
const runCorpus = (): Check[] => CORPUS.map((_, i) => check(i));
const pct = (xs: number[], q: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.ceil(q * xs.length) - 1)]!;

describe("slow machine (simulated)", () => {
  it("passes 750 ms (PreToolUse) and 1,500 ms (PostToolUse) to the engine", () => {
    expect(HARD_STOP_MS).toEqual({ pre: 750, post: 1500 });
  });

  it("RT-HOOK-26: T-CORPUS on a slowed clock gives the same decisions (no false denies)", () => {
    runCorpus(); // warm the engine twice: the first, cold round has one-off outliers
    runCorpus();
    const normal = runCorpus();
    // Slow the clock so the median check reads ~150 ms: about half the checks are over the
    // engine's 100 ms default (which would have stopped them), and ordinary variation up to
    // ~5x stays under the 750 ms limit.
    const factor = 150 / Math.max(pct(normal.map((c) => c.engineMs), 0.5), 0.05);
    slowClock(factor);
    const slow = runCorpus();
    // A one-off pause (GC, scheduler) can push a single check over the limit on a slowed clock.
    // A real false deny reproduces: anything that differs is run once more, and only a
    // difference that happens again fails the test.
    const suspect = slow.map((c, i) => (c.decision !== normal[i]!.decision || c.hitLimit ? i : -1)).filter((i) => i >= 0);
    const confirmed = suspect.map((i) => ({ i, again: check(i) })).filter(({ i, again }) => again.decision !== normal[i]!.decision || again.hitLimit);
    expect(confirmed.map(({ i, again }) => `${CORPUS[i]!.command.slice(0, 60)}: ${normal[i]!.decision} -> ${again.decision}${again.hitLimit ? " (hit the limit)" : ""}`)).toEqual([]);
    // Not a trivial pass: a large share of checks really were over 100 ms on the slowed clock.
    const slowShare = slow.filter((c) => c.slow).length / slow.length;
    expect(slowShare, `factor ${factor.toFixed(0)}, ${(slowShare * 100).toFixed(0)}% over 100 ms`).toBeGreaterThanOrEqual(0.4);
  });

  it("records checks over 100 ms as slowCheck; fast checks are not marked", () => {
    const env = makeEnv();
    slowClock(400); // a ~1 ms check now reads as ~400 ms: over 100, under 750
    runHook("pre", JSON.stringify(pre(env, "Bash", bash("git status"))), env);
    vi.restoreAllMocks();
    runHook("pre", JSON.stringify(pre(env, "Bash", bash("git status"))), env);
    const [slow, fast] = spooled(env).filter((e) => e.kind === "tool_pre");
    expect(slow!.timing.slowCheck).toBe(true);
    expect(slow!.degraded).toBe(false);
    expect(fast!.timing.slowCheck ?? false).toBe(false);
  });

  it("RT-HOOK-27: a pathological command still hits the limit and is denied as degraded high-risk", () => {
    const env = makeEnv();
    // 2,000 chained commands with substitutions: real work, then made 400x slower.
    const cmd = Array.from({ length: 2000 }, (_, i) => `echo "$(printf %s ${i})" > /tmp/x${i}`).join(" && ");
    slowClock(400);
    const r = runHook("pre", JSON.stringify(pre(env, "Bash", bash(cmd))), env);
    vi.restoreAllMocks();
    const e = spooled(env).find((x) => x.kind === "tool_pre")!;
    expect(e.degradedReasons ?? []).toContain("CP-LIMIT-010");
    expect(decision(r.stdout)).toBe("deny");
  });

  it("RT-HOOK-28: a huge tool result still hits the limit (degraded, recorded)", () => {
    const env = makeEnv();
    const id = toolUseId();
    const input = bash("cat big.json");
    runHook("pre", JSON.stringify(pre(env, "Bash", input, id)), env);
    const fields = Object.fromEntries(Array.from({ length: 2000 }, (_, i) => [`f${i}`, "x".repeat(512)]));
    slowClock(400);
    runHook("post", JSON.stringify(post(env, "Bash", input, id, { stdout: JSON.stringify(fields), stderr: "", interrupted: false, isImage: false })), env);
    vi.restoreAllMocks();
    const e = spooled(env).find((x) => x.kind === "tool_post")!;
    expect(e.degraded).toBe(true);
    expect(e.timing.slowCheck).toBe(true);
  });
});
