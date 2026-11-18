// Rule self-tests (engine-spec §10.2 step 8, invariant I6): every declarative rule's own
// positive cases must produce it and its negative cases must not.
import type { LoadedRuleset, RuleTestCase, SessionContext } from "../types.js";
import { analyzeServerImpl } from "../analysis/manifest.js";
import { checkServerRequestImpl, checkToolCallImpl, checkToolResultImpl } from "../analysis/gate.js";
import { expandFakes } from "./fakes.js";

export interface SelfTestReport { failures: { ruleId: string; reason: string }[] }

function ctxFor(ruleset: LoadedRuleset): SessionContext {
  return {
    sessionId: "selftest", platform: "linux", homeDir: "/home/selftest", cwd: "/home/selftest/project", caseInsensitiveFs: false,
    glassboxDirs: ["/home/selftest/.glassbox"], servers: [], policy: { mode: "balanced" }, ruleset,
  };
}

function fires(ruleId: string, tc: RuleTestCase, ruleset: LoadedRuleset): boolean {
  const t0 = performance.now();
  const ctx = ctxFor(ruleset);
  const input = expandFakes(tc.input);
  const ids = (() => {
    switch (tc.surface) {
      case "manifest": return analyzeServerImpl(input, { ruleset }, t0).findings;
      case "call": return checkToolCallImpl(input, ctx, t0).findings;
      case "result": return checkToolResultImpl(input, ctx, t0).findings;
      case "server-request": return checkServerRequestImpl(input, ctx, t0).findings;
    }
  })();
  return ids.some((f) => f.ruleId === ruleId);
}

export function runRuleSelfTests(ruleset: LoadedRuleset): SelfTestReport {
  const failures: SelfTestReport["failures"] = [];
  for (const r of ruleset.rules) {
    r.testCases.positive.forEach((tc, i) => { if (!fires(r.id, tc, ruleset)) failures.push({ ruleId: r.id, reason: `positive case ${i + 1} did not match` }); });
    r.testCases.negative.forEach((tc, i) => { if (fires(r.id, tc, ruleset)) failures.push({ ruleId: r.id, reason: `negative case ${i + 1} matched` }); });
  }
  return { failures };
}
