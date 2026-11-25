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

/**
 * T-CORPUS commands through the hook, all in one folder: each decision plus what its event
 * recorded, matched by tool_use_id (spool-file order isn't reliable within a millisecond).
 */
function runChecks(indexes: readonly number[]): Check[] {
  const env = makeEnv();
  const runs = indexes.map((i) => {
    const c = CORPUS[i]!;
    const id = toolUseId();
    const payload = c.tool === "Bash" ? pre(env, "Bash", bash(c.command), id) : pre(env, "PowerShell", { command: c.command }, id);
    return { id, d: decision(runHook("pre", JSON.stringify(payload), env).stdout) };
  });
  const byId = new Map(spooled(env).filter((e) => e.kind === "tool_pre").map((e) => [e.callId, e]));
  return runs.map(({ id, d }) => {
    const e = byId.get(id)!;
    return { decision: d, engineMs: e.timing.engineMs, slow: e.timing.slowCheck === true, hitLimit: (e.degradedReasons ?? []).includes("CP-LIMIT-010") };
  });
}
const ALL = CORPUS.map((_, i) => i);
const runCorpus = (): Check[] => runChecks(ALL);
const check = (i: number): Check => runChecks([i])[0]!;
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
    // difference that happens again counts.
    const suspect = slow.map((c, i) => (c.decision !== normal[i]!.decision || c.hitLimit ? i : -1)).filter((i) => i >= 0);
    const again = suspect.map((i) => ({ i, again: check(i) }));
    const label = ({ i, again: a }: { i: number; again: Check }) => `${CORPUS[i]!.command.slice(0, 60)}: ${normal[i]!.decision} -> ${a.decision}${a.hitLimit ? " (hit the limit)" : ""}`;
    // The requirement: no false denies. Any reproducible decision change fails.
    expect(again.filter(({ i, again: a }) => a.decision !== normal[i]!.decision).map(label)).toEqual([]);
    // A normal check may still reach the limit on a slowed clock without changing its decision
    // (a degraded read-only check only warns, and a warn sends nothing). That's allowed for a
    // handful; many would mean the limit is too low for a slow machine.
    const hits = again.filter(({ again: a }) => a.hitLimit);
    expect(hits.length, `normal checks that hit the limit: ${hits.map(label).join("; ")}`).toBeLessThanOrEqual(Math.floor(CORPUS.length / 100));
    // Not a trivial pass: a large share of checks really were over 100 ms on the slowed clock.
    const slowShare = slow.filter((c) => c.slow).length / slow.length;
    expect(slowShare, `factor ${factor.toFixed(0)}, ${(slowShare * 100).toFixed(0)}% over 100 ms`).toBeGreaterThanOrEqual(0.4);
  }, 120_000); // four passes over 532 commands: slow Windows runners need more than the default

  it("records checks over 100 ms as slowCheck; fast checks are not marked", () => {
    // Measure this check's real time first (the bundle runs it faster than the source does),
    // then slow the clock so it reads ~200 ms: over 100, with room under the 750 ms limit.
    // (Whether a check reaches the limit is RT-HOOK-26's subject, not this test's.)
    // Same folder throughout: the engine doesn't count one-time setup (it subtracts it), and a
    // fresh folder can make the first check mostly setup, which would read as ~0 ms.
    const env = makeEnv();
    for (let i = 0; i < 3; i++) runHook("pre", JSON.stringify(pre(env, "Bash", bash("git status"))), env);
    const realMs = Math.max(pct(spooled(env).filter((e) => e.kind === "tool_pre").map((e) => e.timing.engineMs), 0.5), 0.01);
    slowClock(200 / realMs);
    runHook("pre", JSON.stringify(pre(env, "Bash", bash("git status"))), env);
    vi.restoreAllMocks();
    runHook("pre", JSON.stringify(pre(env, "Bash", bash("git status"))), env);
    const [slow, fast] = spooled(env).filter((e) => e.kind === "tool_pre").slice(3);
    expect(slow!.timing.slowCheck, `real ${realMs.toFixed(3)} ms, slowed ${slow!.timing.engineMs.toFixed(0)} ms`).toBe(true);
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
