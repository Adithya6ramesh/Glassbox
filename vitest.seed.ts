// Test seeding for the stress job (scripts/stress.mjs).
// GLASSBOX_TEST_SEED fixes every fast-check property run to one seed, so a failure
// found under a random seed replays exactly with the same seed. Unset: fast-check
// picks its own seed, as before.
import fc from "fast-check";

const raw = process.env.GLASSBOX_TEST_SEED;
if (raw !== undefined && raw !== "") {
  const seed = Number(raw);
  if (!Number.isSafeInteger(seed)) throw new Error(`GLASSBOX_TEST_SEED must be an integer, got ${JSON.stringify(raw)}`);
  fc.configureGlobal({ seed: seed | 0 });
}
