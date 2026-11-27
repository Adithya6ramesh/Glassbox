// The start-up regression gate used by the hook-timing workflow (scripts/timing-gate.mjs).
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// @ts-expect-error: a plain .mjs script without type declarations
import { evaluateGate, startupRatio } from "../scripts/timing-gate.mjs";

type Results = Record<string, { p50: number; p95: number }>;
const r = (nodeP50: number, hookP95: number): Results => ({ "warm node-empty": { p50: nodeP50, p95: nodeP50 + 5 }, "warm pre-allow": { p50: hookP95 - 10, p95: hookP95 } });
const baseline = JSON.parse(fs.readFileSync(fileURLToPath(new URL("../timing-baseline.json", import.meta.url)), "utf8")) as {
  tolerance: number; platforms: Record<string, { ratio: number }>;
};

describe("start-up regression gate", () => {
  it("the baseline file has Linux and Windows ratios and a 20% tolerance", () => {
    expect(baseline.tolerance).toBe(0.2);
    expect(baseline.platforms["linux"]!.ratio).toBeGreaterThan(1);
    expect(baseline.platforms["win32"]!.ratio).toBeGreaterThan(1);
  });

  it("measures the hook relative to Node's own start-up", () => {
    expect(startupRatio(r(25, 100))).toBe(4);
    expect(startupRatio({})).toBeNull();
  });

  it("passes at the baseline and up to +20%", () => {
    const b = baseline.platforms["linux"]!.ratio;
    expect(evaluateGate(r(20, 20 * b), baseline, "linux").status).toBe("pass");
    expect(evaluateGate(r(20, 20 * b * 1.19), baseline, "linux").status).toBe("pass");
  });

  it("fails past +20%", () => {
    const b = baseline.platforms["win32"]!.ratio;
    const g = evaluateGate(r(50, 50 * b * 1.25), baseline, "win32");
    expect(g.status).toBe("fail");
    expect(g.message).toMatch(/25% over baseline/);
  });

  it("a slower or faster runner alone doesn't move the measure", () => {
    const b = baseline.platforms["linux"]!.ratio;
    expect(evaluateGate(r(40, 40 * b), baseline, "linux").status).toBe("pass"); // a runner twice as slow
    expect(evaluateGate(r(12, 12 * b), baseline, "linux").status).toBe("pass"); // twice as fast
  });

  it("platforms without a baseline are skipped, incomplete results fail", () => {
    expect(evaluateGate(r(20, 60), baseline, "darwin").status).toBe("skip");
    expect(evaluateGate({}, baseline, "linux").status).toBe("fail");
  });
});
