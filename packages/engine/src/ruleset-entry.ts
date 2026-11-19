// @glassbox/engine/ruleset: loading signed ruleset caches (engine-spec §10.2).
// Kept out of the main entry so an ordinary hook call doesn't pay for Ed25519 and schema
// validation at start-up (150 ms hook budget). Import this only when a cache file exists.
export { loadRuleset, EMBEDDED_TRUSTED_KEYS, REVOKED_KEY_IDS } from "./ruleset/load.js";
export { runRuleSelfTests, type SelfTestReport } from "./ruleset/selftest.js";
export { BASELINE_TEST_CASES } from "./ruleset/baseline-tests.generated.js";
export type { LoadedRuleset, LoadRulesetOptions, TrustedKey } from "./types.js";
