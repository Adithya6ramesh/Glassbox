// The engine's built-in tool table must match the hand-updated list of tools in the Claude Code
// docs (test/fixtures/claude-code-tools.json). A tool the docs list but the engine doesn't know
// would be treated as unanalyzable (safe, but noisy); a wrong category could be unsafe.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BUILTIN_TOOLS, type BuiltinToolCategory } from "../../src/index.js";
import { builtin } from "../helpers.js";

interface Fixture { tools: Record<string, BuiltinToolCategory>; legacy: Record<string, BuiltinToolCategory | string> }
const fx = JSON.parse(readFileSync(new URL("../fixtures/claude-code-tools.json", import.meta.url), "utf8")) as Fixture;
const entries = (o: Record<string, string>) => Object.entries(o).filter(([k]) => !k.startsWith("$"));
const expected = Object.fromEntries([...entries(fx.tools), ...entries(fx.legacy)]);

describe("built-in tool inventory", () => {
  it("every tool in the docs list is known to the engine, with the same category", () => {
    for (const [name, cat] of entries(fx.tools)) expect(BUILTIN_TOOLS[name], name).toBe(cat);
  });

  it("the engine knows no tool that isn't in the docs list or the legacy list", () => {
    expect(Object.keys(BUILTIN_TOOLS).sort()).toEqual(Object.keys(expected).sort());
    for (const [name, cat] of Object.entries(BUILTIN_TOOLS)) expect(expected[name], name).toBe(cat);
  });

  it("no known tool is classified as unanalyzable just for being unknown", () => {
    for (const name of Object.keys(expected)) {
      const reasons = builtin(name, {}).actionRisk.reasons.join(" ");
      expect(reasons, name).not.toContain("unknown agent tool");
    }
  });

  it("command tools are analyzed as commands; read tools stay reads", () => {
    for (const [name, cat] of Object.entries(BUILTIN_TOOLS)) {
      // A home-folder wipe written for each shell. (`rm -rf ~` isn't one in PowerShell: no
      // Remove-Item parameter starts with "rf", so PowerShell refuses to run it.)
      const wipe = name === "PowerShell" ? "Remove-Item -Recurse -Force ~" : "rm -rf ~";
      if (cat === "command") expect(builtin(name, { command: wipe }).verdict, name).toBe("deny");
      if (cat === "read") expect(builtin(name, {}).actionRisk.level, name).toBe("read");
    }
  });
});
