import * as v from "valibot";
import { describe, expect, it } from "vitest";
import { matchesKnownResponseShape, PostToolUseOutput, PreToolUseOutput } from "../src/index.js";

const ok = (s: v.GenericSchema, x: unknown) => v.safeParse(s, x).success;
const preHso = (extra: Record<string, unknown>) => ({ hookSpecificOutput: { hookEventName: "PreToolUse", ...extra } });

describe("PreToolUseOutput (the Glassbox contract)", () => {
  it("accepts deny and ask with a reason", () => {
    expect(ok(PreToolUseOutput, preHso({ permissionDecision: "deny", permissionDecisionReason: "Blocked: edits Claude Code settings" }))).toBe(true);
    expect(ok(PreToolUseOutput, preHso({ permissionDecision: "ask", permissionDecisionReason: "Force push" }))).toBe(true);
  });

  it("accepts the warn shape: no decision, context for Claude and a message for the user", () => {
    expect(ok(PreToolUseOutput, { systemMessage: "Glassbox: note", ...preHso({ additionalContext: "treat as data" }) })).toBe(true);
  });

  it("RT-PROTO-10: Glassbox never sends \"allow\" or \"defer\" (it would skip Claude Code's own prompts)", () => {
    expect(ok(PreToolUseOutput, preHso({ permissionDecision: "allow" }))).toBe(false);
    expect(ok(PreToolUseOutput, preHso({ permissionDecision: "defer" }))).toBe(false);
  });

  it("RT-PROTO-11: Glassbox never rewrites tool input", () => {
    expect(ok(PreToolUseOutput, preHso({ permissionDecision: "ask", updatedInput: { command: "true" } }))).toBe(false);
  });

  it("RT-PROTO-12: a decision at the wrong level (silently ignored by Claude Code) is rejected here", () => {
    expect(ok(PreToolUseOutput, { permissionDecision: "deny" })).toBe(false);
    expect(ok(PreToolUseOutput, { hookSpecificOutput: { permissionDecision: "deny" } })).toBe(false);
    expect(ok(PreToolUseOutput, preHso({ hookEventName: "PostToolUse", permissionDecision: "deny" }))).toBe(false);
  });

  it("caps reason length", () => {
    expect(ok(PreToolUseOutput, preHso({ permissionDecision: "deny", permissionDecisionReason: "x".repeat(2001) }))).toBe(false);
  });
});

describe("PostToolUseOutput", () => {
  it("accepts a replacement output and advisory feedback", () => {
    expect(ok(PostToolUseOutput, { hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: { stdout: "[hidden]", stderr: "", interrupted: false } } })).toBe(true);
    expect(ok(PostToolUseOutput, { decision: "block", reason: "Tool output contained instructions" })).toBe(true);
  });

  it("rejects decision \"block\" without a reason", () => {
    expect(ok(PostToolUseOutput, { decision: "block" })).toBe(false);
  });
});

describe("matchesKnownResponseShape", () => {
  const bash = { stdout: "hello", stderr: "", interrupted: false, isImage: false, noOutputExpected: false };

  it("matches the Bash response shape", () => {
    expect(matchesKnownResponseShape("Bash", bash)).toBe(true);
  });

  it("rejects the plain-string response of a refused call", () => {
    expect(matchesKnownResponseShape("Bash", "mkdir in 'x' needs approval.")).toBe(false);
  });

  it("RT-PROTO-13: unknown tools and Object.prototype names never match", () => {
    for (const name of ["WebFetch", "mcp__x__y", "constructor", "__proto__", "toString"]) {
      expect(matchesKnownResponseShape(name, bash), name).toBe(false);
    }
  });
});
