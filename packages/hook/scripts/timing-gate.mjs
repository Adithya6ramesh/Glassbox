// Regression gate for hook start-up time (owner decision 2026-11-27).
//
// The measure is the warm pre-allow p95 divided by the bare `node -e ""` p50 on the same runner.
// Raw milliseconds on shared CI runners swing by about 2x from run to run (Linux 57-107 ms,
// Windows 94-415 ms for the same bundle); relative to Node's own start-up they are much steadier
// (Linux ~3.2-4.4, Windows ~2.3-2.8). So "the hook got ~20% slower" is checked as this ratio
// rising more than `tolerance` above the baseline. A breach is measured again (see timing.mjs):
// a real regression persists, a runner hiccup doesn't.

/** Hook p95 relative to Node's own start-up p50 on the same machine. */
export function startupRatio(results) {
  const hook = results["warm pre-allow"]?.p95;
  const node = results["warm node-empty"]?.p50;
  if (!(hook > 0) || !(node > 0)) return null;
  return hook / node;
}

/**
 * Compare one measurement with the baseline file for this platform.
 * Returns { status: "pass" | "fail" | "skip", ratio, limit, message }.
 */
export function evaluateGate(results, baseline, platform) {
  const b = baseline?.platforms?.[platform];
  if (!b || !(b.ratio > 0)) return { status: "skip", ratio: null, limit: null, message: `no timing baseline for ${platform}` };
  const tolerance = typeof baseline.tolerance === "number" && baseline.tolerance > 0 ? baseline.tolerance : 0.2;
  const ratio = startupRatio(results);
  const limit = b.ratio * (1 + tolerance);
  if (ratio === null) return { status: "fail", ratio, limit, message: "timing results are incomplete" };
  const pct = ((ratio / b.ratio - 1) * 100).toFixed(0);
  return ratio <= limit
    ? { status: "pass", ratio, limit, message: `ratio ${ratio.toFixed(2)} vs baseline ${b.ratio} (${pct}%, limit +${(tolerance * 100).toFixed(0)}%)` }
    : { status: "fail", ratio, limit, message: `ratio ${ratio.toFixed(2)} is ${pct}% over baseline ${b.ratio} (limit +${(tolerance * 100).toFixed(0)}%)` };
}
