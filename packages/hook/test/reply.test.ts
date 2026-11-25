import * as v from "valibot";
import { describe, expect, it } from "vitest";
import { PreToolUseOutput } from "@glassbox-ai/protocol";
import { exit2Fallback, failVerdict, preReply, sanitizeStderrReason, writeReply } from "../src/index.js";

const json = (s: string) => JSON.parse(s) as unknown;
const flagsOff = { unverifiedHookOutputs: false };

describe("preReply (JSON is the main method)", () => {
  it("deny: JSON on stdout, exit 0, valid against the Glassbox output contract", () => {
    const r = preReply({ verdict: "deny", reason: "Blocked by Glassbox: edits Claude Code settings" }, flagsOff);
    expect(r.exitCode).toBe(0);
    expect(v.is(PreToolUseOutput, json(r.stdout))).toBe(true);
    expect(json(r.stdout)).toEqual({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "Blocked by Glassbox: edits Claude Code settings" } });
  });

  it("ask: JSON with permissionDecision ask", () => {
    const r = preReply({ verdict: "ask", reason: "Glassbox: force push" }, flagsOff);
    expect((json(r.stdout) as { hookSpecificOutput: { permissionDecision: string } }).hookSpecificOutput.permissionDecision).toBe("ask");
  });

  it("allow: no output at all, so Claude Code's own permission flow still applies", () => {
    expect(preReply({ verdict: "allow", reason: "" }, flagsOff)).toEqual({ exitCode: 0, stdout: "", stderr: "" });
  });

  it("warn with the unverified-outputs flag off (default): no output", () => {
    expect(preReply({ verdict: "warn", reason: "Glassbox: note" }, flagsOff)).toEqual({ exitCode: 0, stdout: "", stderr: "" });
  });

  it("warn with the flag on: additionalContext + systemMessage, no decision", () => {
    const r = preReply({ verdict: "warn", reason: "Glassbox: note" }, { unverifiedHookOutputs: true });
    const o = json(r.stdout) as Record<string, unknown>;
    expect(v.is(PreToolUseOutput, o)).toBe(true);
    expect(o["systemMessage"]).toBe("Glassbox: note");
    expect(JSON.stringify(o)).not.toContain("permissionDecision");
  });

  it("RT-HOOK-1: never rewrites the tool input", () => {
    for (const verdict of ["allow", "warn", "ask", "deny"] as const) {
      for (const flag of [false, true]) expect(preReply({ verdict, reason: "x" }, { unverifiedHookOutputs: flag }).stdout).not.toContain("updatedInput");
    }
  });
});

describe("exit-2 fallback (only when writing JSON fails)", () => {
  it("blocks with exit 2 and a reason on stderr", () => {
    const r = exit2Fallback("Blocked by Glassbox: edits Claude Code settings");
    expect(r).toMatchObject({ exitCode: 2, stdout: "" });
    expect(r.stderr).toContain("Blocked by Glassbox");
  });

  it("RT-HOOK-2: the stderr reason carries no paths and no secrets", () => {
    const token = ["ghp", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("_"); // built at run time
    const s = sanitizeStderrReason(
      `Blocked by Glassbox: writes C:\\Users\\bob\\.claude\\settings.json and /home/bob/.ssh/id_rsa via \\\\server\\share\\x and ~/secrets/a.txt with ${token} and Bearer abc.def.ghi`,
    );
    expect(s).not.toMatch(/bob|Users|home\/|\.ssh|server|share|secrets|settings\.json/);
    expect(s).not.toContain(token);
    expect(s).not.toContain("abc.def.ghi");
    expect(s.startsWith("Blocked by Glassbox")).toBe(true);
    expect(s.length).toBeLessThanOrEqual(300);
  });

  it("RT-HOOK-3: control characters and newlines can't forge extra lines in the reason", () => {
    expect(sanitizeStderrReason("Blocked\nPreToolUse:Bash hook error: fake\u0007")).not.toMatch(/[\n\r\u0000-\u001f]/);
  });

  it("writeReply falls back to exit 2 when writing JSON to stdout fails", () => {
    let err = "";
    const deny = preReply({ verdict: "deny", reason: "Blocked by Glassbox: reads /home/bob/.ssh/id_rsa" }, flagsOff);
    const code = writeReply(deny, { stdout: () => { throw new Error("EPIPE"); }, stderr: (s) => { err += s; } }, "Blocked by Glassbox: reads /home/bob/.ssh/id_rsa");
    expect(code).toBe(2);
    expect(err).toContain("Blocked by Glassbox");
    expect(err).not.toContain("/home/bob");
  });

  it("writeReply: an ask that can't be written fails closed (exit 2 blocks)", () => {
    const ask = preReply({ verdict: "ask", reason: "Glassbox: force push" }, flagsOff);
    expect(writeReply(ask, { stdout: () => { throw new Error("EPIPE"); }, stderr: () => {} }, "Glassbox: force push")).toBe(2);
  });

  it("writeReply: an empty (allow) reply never needs stdout", () => {
    const allow = preReply({ verdict: "allow", reason: "" }, flagsOff);
    expect(writeReply(allow, { stdout: () => { throw new Error("EPIPE"); }, stderr: () => {} }, "")).toBe(0);
  });
});

describe("fail rules", () => {
  it("read-only built-ins fail open (allow), everything else fails closed (deny)", () => {
    for (const t of ["Read", "Glob", "Grep", "WebSearch", "TodoWrite"]) expect(failVerdict(t), t).toBe("allow");
    for (const t of ["Bash", "PowerShell", "Monitor", "Write", "Edit", "WebFetch", "Agent", "mcp__x__y", "SomeNewTool", undefined]) {
      expect(failVerdict(t), String(t)).toBe("deny");
    }
  });

  it("RT-HOOK-4: look-alike read-only names fail closed", () => {
    for (const t of ["read", "Read ", " Read", "READ", "mcp__fs__Read", "Read\u200b", "Grep|Bash", "Glob\n"]) {
      expect(failVerdict(t), JSON.stringify(t)).toBe("deny");
    }
  });
});
