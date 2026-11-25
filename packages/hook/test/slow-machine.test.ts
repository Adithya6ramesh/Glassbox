// A slow machine, simulated: the clock the engine and hook read (performance.now) runs N times
// faster than real time, so every check looks N times slower. The hook passes the engine
// 750 ms (PreToolUse) and 1,500 ms (PostToolUse) instead of the engine's 100 ms default.
// - Normal inputs (the T-CORPUS commands) on a slowed clock give the same verdicts as on a
//   normal clock: no false denies from the time limit.
// - Checks over 100 ms are recorded as slowCheck in the event.
// - Huge or pathological inputs still hit the limit (CP-LIMIT-010) and are treated as degraded.
import { afterEach, describe, expect, it, vi } from "vitest";
import { CORPUS } from "../../engine/test/corpus/claude-code-commands.js";
import { eventLine, HARD_STOP_MS, runHook, SLOW_CHECK_MS } from "../src/index.js";
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
    // The simulated machine is defined by its heaviest normal checks: slow the clock until the
    // 99th-percentile check reads ~375 ms, half the 750 ms limit. (Until 2026-11-26 the median was
    // set to 150 ms; on fast runners that meant a slowdown of ~3,000x, and heavy commands such as
    // `rm -rf node_modules && pnpm install` then crossed 750 ms and were denied as degraded
    // high-risk calls: the limit working, at an unrealistic speed.)
    const factor = 375 / Math.max(pct(normal.map((c) => c.engineMs), 0.99), 0.05);
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
    // Every event's slowCheck matches its own recorded time, on both clocks.
    for (const c of [...normal, ...slow]) expect(c.slow, `engineMs ${c.engineMs}`).toBe(c.engineMs > 100);
    // Not a trivial pass: the heavier checks really were over 100 ms on the slowed clock, so the
    // engine's 100 ms default would have degraded them (and denied the high-risk ones).
    const slowShare = slow.filter((c) => c.slow).length / slow.length;
    expect(slowShare, `factor ${factor.toFixed(0)}, ${(slowShare * 100).toFixed(1)}% over 100 ms`).toBeGreaterThanOrEqual(0.05);
  }, 120_000); // four passes over 532 commands: slow Windows runners need more than the default

  // Rewritten 2026-11-26: the earlier version slowed one real check to ~200 ms and expected
  // slowCheck, but the engine intermittently reports a check's time as ~0 ms on CI (it
  // subtracts what it counts as one-time setup), so producing one slow check isn't reliable.
  // The property is tested exactly instead, here and in RT-HOOK-26 (every event, slowed clock).
  it("records exactly the checks over 100 ms as slowCheck", () => {
    const base = { sessionId: "00000000-0000-4000-8000-0000000000aa", mode: "balanced" as const, project: { idHash: "a".repeat(64), label: "p" }, degradedReasons: [] };
    const slowOf = (engineMs: number) => (JSON.parse(eventLine(base, { kind: "session_start", engineMs })!) as { timing: { slowCheck?: boolean } }).timing.slowCheck;
    expect(SLOW_CHECK_MS).toBe(100);
    expect(slowOf(100.01)).toBe(true);
    expect(slowOf(750)).toBe(true);
    expect(slowOf(100)).toBeUndefined();
    expect(slowOf(3)).toBeUndefined();
    expect(slowOf(0)).toBeUndefined();
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
