// The only host API the engine may use (engine-spec §1.1): a monotonic clock,
// used for Decision.elapsedMs and the hardStopMs backstop, never for logic.
declare const performance: { now(): number };
