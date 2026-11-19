// Time spent on one-time initialization (compiling linear regexes, building lookup tables).
// The per-call hardStopMs backstop excludes it, so a cold first call isn't mistaken for a
// pathological input. Pure bookkeeping: it never changes a result.
let total = 0;

export function initTimed<T>(fn: () => T): T {
  const t = performance.now();
  try {
    return fn();
  } finally {
    total += performance.now() - t;
  }
}

export function initMs(): number {
  return total;
}
