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
const pct = (xs: number[], q: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.ceil(q * xs.length) - 1)]!;

describe("slow machine (simulated)", () => {
  it("passes 750 ms (PreToolUse) and 1,500 ms (PostToolUse) to the engine", () => {
    expect(HARD_STOP_MS).toEqual({ pre: 750, post: 1500 });
  });

  // Noise only ever adds time (GC, scheduler, a loaded CI runner), so every measurement here is
  // the minimum over 3 passes, and a slowed-clock result counts only if it happens in all 3.
  // A real false deny happens every time; a load spike doesn't hit the same command 3 times.
  // (History: tuned on 2026-11-26 from a median-based factor, then a p99-based one with a single
  // re-run; both flaked in the 50-run stress job under parallel load.)
  it("RT-HOOK-26: T-CORPUS on a slowed clock gives the same decisions (no false denies)", () => {
    runCorpus(); // warm-up: the first, cold pass has one-off outliers
    const normal = [runCorpus(), runCorpus(), runCorpus()];
    const minNormal = ALL.map((i) => Math.min(...normal.map((p) => p[i]!.engineMs)));
    // The simulated machine is defined by its heaviest normal checks: the 99th-percentile
    // command reads ~375 ms, half the 750 ms limit.
    const factor = 375 / Math.max(pct(minNormal, 0.99), 0.05);
    slowClock(factor);
    const slow = [runCorpus(), runCorpus(), runCorpus()];
    vi.restoreAllMocks();

    const base = normal[0]!;
    const always = (pred: (c: Check, i: number) => boolean) => ALL.filter((i) => slow.every((p) => pred(p[i]!, i)));
    const label = (i: number) => `${CORPUS[i]!.command.slice(0, 60)}: ${base[i]!.decision} -> ${slow.map((p) => p[i]!.decision).join("/")}${slow.every((p) => p[i]!.hitLimit) ? " (hit the limit)" : ""}`;
    // The requirement: no false denies. A decision change in all 3 slowed passes fails.
    expect(always((c, i) => c.decision !== base[i]!.decision).map(label)).toEqual([]);
    // A normal check may reach the limit without changing its decision (a degraded read-only
    // check only warns, and a warn sends nothing): allowed for a handful (1%), not more.
    const hits = always((c) => c.hitLimit);
    expect(hits.length, `normal checks that always hit the limit: ${hits.map(label).join("; ")}`).toBeLessThanOrEqual(Math.floor(CORPUS.length / 100));
    // Every event's slowCheck matches its own recorded time, on both clocks.
    for (const c of [...normal, ...slow].flat()) expect(c.slow, `engineMs ${c.engineMs}`).toBe(c.engineMs > 100);
    // Not a trivial pass: some checks were over 100 ms in every slowed pass, so the engine's
    // 100 ms default would have degraded them (and denied the high-risk ones).
    const over100 = always((c) => c.engineMs > 100).length;
    expect(over100, `factor ${factor.toFixed(0)}: ${over100} of ${CORPUS.length} commands over 100 ms in all 3 slowed passes`).toBeGreaterThanOrEqual(Math.floor(CORPUS.length / 100));
  }, 180_000); // seven passes over 532 commands: slow Windows runners need more than the default

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
