// Regex rule anchors (spec rev 6, Q1): literals of which every match contains one. The
// engine skips a regex when none occurs in the (lowercased) text, so a wrong anchor would
// silently disable a rule. These tests prove every baseline anchor set is sound.
import { describe, expect, it } from "vitest";
import { EMBEDDED_BASELINE, type LoadedRuleset, type Matcher, type RuleDef } from "../../src/index.js";
import { BASELINE_TEST_CASES, runRuleSelfTests } from "../../src/ruleset-entry.js";
import * as v from "valibot";
import { validateRules } from "../../src/ruleset/load.js";
import { RuleSchema } from "../../src/ruleset/schema.js";
import { anchorsCover, requiredLiterals } from "./regex-literals.js";

type Regex = Extract<Matcher, { type: "regex" }>;
function regexes(m: Matcher): Regex[] {
  if (m.type === "regex") return [m];
  if (m.type === "all" || m.type === "any") return m.of.flatMap(regexes);
  if (m.type === "not") return regexes(m.of);
  return [];
}
const RULES = EMBEDDED_BASELINE.rules.flatMap((r) => regexes(r.matcher).map((m, i) => ({ id: `${r.id}#${i}`, m })));

describe("the regex-literal analyzer (the tool that checks anchors)", () => {
  it.each([
    ["abc", ["abc"]],
    ["a(b|c)d", ["abd", "acd"]],
    ["foo\\s*bar", ["foo", "bar"]], // either is required; it keeps one of them
    ["(?i)Hello", ["hello"]],
    ["x[0-9]{2}y", null], // classes > 8 chars become "any char": x and y alone are still required
  ])("%s", (pattern, expected) => {
    const r = requiredLiterals(pattern);
    if (pattern === "foo\\s*bar") expect(r === null ? [] : r.filter((x) => x === "foo" || x === "bar").length).toBe(1);
    else if (pattern === "x[0-9]{2}y") expect(r).not.toBeNull();
    else expect(r?.sort()).toEqual((expected as string[]).sort());
  });

  it("gives up on patterns with no required literal", () => {
    expect(requiredLiterals(".*")).toBeNull();
    expect(requiredLiterals("a?b?")).toBeNull();
    expect(requiredLiterals("(foo|.*)")).toBeNull();
  });

  it("rejects anchors that some match lacks", () => {
    expect(anchorsCover("(foo|bar)baz", ["foo"]).ok).toBe(false);
    expect(anchorsCover("(foo|bar)baz", ["foo", "bar"]).ok).toBe(true);
    expect(anchorsCover("(foo|bar)baz", ["baz"]).ok).toBe(true);
    expect(anchorsCover("foo|bar", ["fo"]).ok).toBe(false);
    expect(anchorsCover(".*x", ["x"]).ok).toBe(true);
    expect(anchorsCover(".*", ["x"]).ok).toBe(false);
  });
});

describe("baseline regex rules", () => {
  it("there are regex rules to check", () => {
    expect(RULES.length).toBeGreaterThanOrEqual(9);
  });

  it.each(RULES)("$id has anchors", ({ m }) => {
    expect(m.anchors?.length ?? 0).toBeGreaterThan(0);
  });

  it.each(RULES)("$id: every required literal contains an anchor (sound)", ({ m }) => {
    const r = anchorsCover(m.pattern, m.anchors ?? []);
    expect(r.uncovered).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it.each(RULES)("$id: anchors are selective (ASCII anchors have at least 3 characters)", ({ m }) => {
    // Short anchors are sound but almost always present, so they skip nothing. "![" is the
    // one deliberate exception (markdown image syntax).
    const weak = (m.anchors ?? []).filter((a) => a.length < 3 && [...a].every((c) => c >= " " && c <= "~") && a !== "![");
    expect(weak).toEqual([]);
  });

  it("every baseline rule passes the signed-payload rule schema (the build doesn't check it)", () => {
    // Found while splitting CP-POISON-003: an "any" without scope "field" built and passed every
    // rule self-test, but a signed ruleset containing it fell back to the embedded baseline.
    const bad = EMBEDDED_BASELINE.rules.filter((r) => !v.safeParse(RuleSchema, r).success).map((r) => r.id);
    expect(bad).toEqual([]);
  });

  it("the loader accepts the baseline anchors", () => {
    expect(validateRules({ ...EMBEDDED_BASELINE, channel: "baseline", rules: EMBEDDED_BASELINE.rules } as never)).toEqual([]);
  });

  it("every rule's own test cases give the same result with and without anchors", () => {
    const strip = (m: Matcher): Matcher => {
      if (m.type === "regex") { const { anchors: _a, ...rest } = m; void _a; return rest; }
      if (m.type === "all" || m.type === "any") return { ...m, of: m.of.map(strip) };
      if (m.type === "not") return { ...m, of: strip(m.of) };
      return m;
    };
    const stripped: LoadedRuleset = { ...EMBEDDED_BASELINE, rules: EMBEDDED_BASELINE.rules.map((r): RuleDef => ({ ...r, matcher: strip(r.matcher) })) };
    expect(runRuleSelfTests(stripped, BASELINE_TEST_CASES).failures).toEqual([]);
    expect(runRuleSelfTests(EMBEDDED_BASELINE, BASELINE_TEST_CASES).failures).toEqual([]);
  });
});

describe("the loader rejects unsafe anchors", () => {
  const rule = (anchors: string[], flags?: "i"): RuleDef => ({
    ...(EMBEDDED_BASELINE.rules.find((r) => r.matcher.type === "regex") as RuleDef),
    id: "CP-TEST-001",
    matcher: { type: "regex", pattern: "foo", anchors, ...(flags ? { flags } : {}) },
  });
  const errs = (r: RuleDef) => validateRules({ ...EMBEDDED_BASELINE, channel: "baseline", rules: [r] } as never);

  it("uppercase", () => { expect(errs(rule(["Foo"])).join()).toMatch(/lowercase/); });
  it("non-ASCII on a case-insensitive regex", () => { expect(errs(rule(["fóo"], "i")).join()).toMatch(/non-ASCII/); });
  it("non-ASCII on a case-sensitive regex is fine", () => { expect(errs(rule(["fóo"]))).toEqual([]); });
  it("Greek sigma", () => { expect(errs(rule(["σx"])).join()).toMatch(/sigma/); });
});
