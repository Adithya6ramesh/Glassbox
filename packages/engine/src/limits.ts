import type { Limits } from "./types.js";

export const DEFAULT_LIMITS: Readonly<Limits> = Object.freeze({
  maxInputBytes: 1024 * 1024,
  maxDepth: 32,
  maxNodes: 100_000,
  maxTools: 500,
  maxDescriptionBytes: 16 * 1024,
  maxFieldScanBytes: 64 * 1024,
  maxCommandBytes: 16 * 1024,
  maxSqlBytes: 64 * 1024,
  maxDecodeDepth: 2,
  maxDecodedBytes: 256 * 1024,
  maxFindings: 200,
  maxStringBytes: 1024 * 1024,
  timeBudgetMs: 20,
  hardStopMs: 100,
  signalTtlCalls: 50,
  minConfidenceForVerdict: 0.3,
});

export function resolveLimits(over: unknown): Limits {
  const out: Limits = { ...DEFAULT_LIMITS };
  if (over === null || typeof over !== "object") return out;
  for (const k of Object.keys(DEFAULT_LIMITS) as (keyof Limits)[]) {
    const v = (over as Record<string, unknown>)[k];
    if (typeof v === "number" && Number.isFinite(v) && v >= 0) out[k] = v;
  }
  return out;
}
