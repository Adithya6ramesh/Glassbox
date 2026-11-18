// T-CORPUS: per-mode ask rate on real-style Claude Code commands, with a regression gate.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { checkToolCall, type ApprovalMode, type Verdict } from "../../src/index.js";
import { ctx, MODES, winCtx } from "../helpers.js";
import { CORPUS } from "./claude-code-commands.js";

const baseline = JSON.parse(readFileSync(new URL("./ask-rate.baseline.json", import.meta.url), "utf8")) as Record<ApprovalMode, { ask: number; deny: number }>;

function run(mode: ApprovalMode) {
  const counts: Record<Verdict, number> = { allow: 0, warn: 0, ask: 0, deny: 0 };
  const mismatches: string[] = [];
  for (const e of CORPUS) {
    const c = e.tool === "PowerShell" ? winCtx({ policy: { mode } }) : ctx({ policy: { mode } });
    const d = checkToolCall({ serverId: "builtin", toolName: e.tool, arguments: { command: e.command } }, c);
    counts[d.verdict]++;
    if (mode === "balanced" && d.verdict !== e.balanced) mismatches.push(`${e.tool}: ${JSON.stringify(e.command)} → ${d.verdict}, expected ${e.balanced}`);
  }
  return { counts, mismatches };
}

describe("T-CORPUS: real-style Claude Code commands", () => {
  it("has at least 500 commands", () => {
    expect(CORPUS.length).toBeGreaterThanOrEqual(500);
  });

  it("balanced verdicts match the labels", () => {
    expect(run("balanced").mismatches).toEqual([]);
  });

  it.each(MODES)("%s: ask/deny rate does not regress above the recorded baseline", (mode) => {
    const { counts } = run(mode);
    const n = CORPUS.length;
    const rate = { ask: counts.ask / n, deny: counts.deny / n };
    console.log(`[T-CORPUS] ${mode}: n=${n} allow=${counts.allow} warn=${counts.warn} ask=${counts.ask} (${(rate.ask * 100).toFixed(1)}%) deny=${counts.deny} (${(rate.deny * 100).toFixed(1)}%)`);
    expect(rate.ask).toBeLessThanOrEqual(baseline[mode].ask + 0.005);
    expect(rate.deny).toBeLessThanOrEqual(baseline[mode].deny + 0.005);
    if (mode === "autopilot") expect(counts.ask).toBe(0);
  });
});
