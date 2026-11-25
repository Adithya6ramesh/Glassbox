// Real Claude Code 2.1.332 payloads (see fixtures/claude-code/2.1.332-win32/README.md).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as v from "valibot";
import { describe, expect, it } from "vitest";
import { exitCodeFromFailure, matchesKnownResponseShape, parseHookInput, PreToolUseOutput, TOOL_RESPONSE_SHAPES, type KnownHookEvent } from "../src/index.js";

const ROOT = fileURLToPath(new URL("./fixtures/claude-code/2.1.332-win32/", import.meta.url));

function jsonFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? jsonFiles(p) : e.name.endsWith(".json") ? [p] : [];
  });
}
const load = (f: string) => JSON.parse(fs.readFileSync(f, "utf8")) as Record<string, unknown>;
const rel = (f: string) => path.relative(ROOT, f).replaceAll("\\", "/");

const inputFiles = jsonFiles(path.join(ROOT, "input"));
const outputFiles = jsonFiles(path.join(ROOT, "output"));

type OutputFixture = {
  tool_name: string;
  scenario: { run: string; mode: "-p" | "interactive"; replyMethod: "json" | "exit2" | "none"; hookShell: string; permissionMode: string };
  hookStdin: Record<string, unknown>;
  hookReply: { exitCode: number; stdout: { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } } | null; stderr: string | null };
  permissionRequest?: Record<string, unknown>;
  observed: { toolRan: boolean; claudeSaw: string | null; permissionRequestFired?: boolean; postToolBatchFired?: boolean; promptShown?: string };
};
const outputs = outputFiles.map((f) => ({ file: rel(f), decision: path.basename(f).split(".")[0]!.replace("output-", ""), fx: load(f) as unknown as OutputFixture }));

describe("input fixtures (what Claude Code sends)", () => {
  it("are all present", () => {
    expect(inputFiles.length).toBe(65);
  });

  it("every payload parses as its own event", () => {
    for (const f of inputFiles) {
      const j = load(f);
      const r = parseHookInput(j, j["hook_event_name"] as KnownHookEvent);
      expect(r.ok && r.known, rel(f)).toBe(true);
    }
  });

  it("every captured response of a shaped tool matches its shape", () => {
    let checked = 0;
    for (const f of inputFiles) {
      const j = load(f);
      if (j["hook_event_name"] !== "PostToolUse" || !Object.hasOwn(TOOL_RESPONSE_SHAPES, j["tool_name"] as string)) continue;
      checked++;
      expect(matchesKnownResponseShape(j["tool_name"] as string, j["tool_response"]), rel(f)).toBe(true);
    }
    expect(checked).toBeGreaterThanOrEqual(10);
  });

  it("a failed Bash command carries its exit code in PostToolUseFailure", () => {
    const j = load(path.join(ROOT, "input/run1/PostToolUseFailure.Bash.json"));
    expect(exitCodeFromFailure(j["error"] as string)).toBe(2);
  });

  it("RT-PROTO-23: commands Claude Code auto-approves still reach PreToolUse", () => {
    for (const [file, command] of [["PreToolUse.Bash.json", "whoami"], ["PreToolUse.PowerShell.json", "Get-Date"], ["PreToolUse.Monitor.json", "echo tick"]] as const) {
      const j = load(path.join(ROOT, "input/run2", file));
      expect((j["tool_input"] as Record<string, unknown>)["command"], file).toBe(command);
    }
    expect(fs.readdirSync(path.join(ROOT, "input/run2")).some((f) => f.startsWith("PermissionRequest"))).toBe(false);
  });
});

describe("output fixtures (what a hook reply does)", () => {
  it("are all present", () => {
    expect(outputs.length).toBe(41);
    expect(outputs.filter((o) => o.fx.scenario.mode === "interactive").length).toBe(2);
  });

  it("every hook stdin is a PreToolUse payload and every JSON reply fits the Glassbox contract", () => {
    for (const { file, fx } of outputs) {
      expect(parseHookInput(fx.hookStdin, "PreToolUse").ok, file).toBe(true);
      if (fx.hookReply.stdout !== null) expect(v.is(PreToolUseOutput, fx.hookReply.stdout), file).toBe(true);
    }
  });

  it("deny blocks the call, ask in -p refuses it, no decision lets it run", () => {
    for (const { file, decision, fx } of outputs) {
      expect(fx.observed.toolRan, file).toBe(decision === "none");
    }
  });

  it("JSON deny: Claude sees \"PreToolUse:<tool> hook error: <reason>\" and nothing else", () => {
    const denies = outputs.filter((o) => o.decision === "deny" && o.fx.scenario.replyMethod === "json");
    expect(denies.length).toBeGreaterThan(0);
    for (const { file, fx } of denies) {
      const reason = fx.hookReply.stdout!.hookSpecificOutput.permissionDecisionReason;
      expect(fx.observed.claudeSaw, file).toBe(`PreToolUse:${fx.tool_name} hook error: ${reason}`);
    }
  });

  it("ask in -p mode: Claude sees exactly the reason", () => {
    const asks = outputs.filter((o) => o.decision === "ask" && o.fx.scenario.mode === "-p");
    expect(asks.length).toBeGreaterThan(0);
    for (const { file, fx } of asks) {
      expect(fx.observed.claudeSaw, file).toBe(fx.hookReply.stdout!.hookSpecificOutput.permissionDecisionReason);
    }
  });

  it("ask in an interactive session: Claude Code's prompt shows our reason and fires PermissionRequest", () => {
    for (const { file, fx } of outputs.filter((o) => o.fx.scenario.mode === "interactive")) {
      const reason = fx.hookReply.stdout!.hookSpecificOutput.permissionDecisionReason;
      expect(fx.observed.promptShown, file).toContain(reason);
      expect(fx.observed.permissionRequestFired, file).toBe(true);
      expect(parseHookInput(fx.permissionRequest, "PermissionRequest").ok, file).toBe(true);
      expect(fx.scenario.permissionMode, file).toBe("auto"); // our ask still prompts in auto mode
    }
  });

  it("RT-PROTO-28: an interactive No leaves no follow-up event (no PostToolUse, no PostToolBatch)", () => {
    for (const { file, fx } of outputs.filter((o) => o.fx.scenario.mode === "interactive")) {
      expect(fx.observed.toolRan, file).toBe(false);
      expect(fx.observed.postToolBatchFired, file).toBe(false);
      expect(fx.observed.claudeSaw, file).toBeNull();
    }
  });

  it("RT-PROTO-24: an exit-2 deny shows Claude the hook command line; a JSON deny doesn't", () => {
    const exit2 = outputs.filter((o) => o.decision === "deny" && o.fx.scenario.replyMethod === "exit2");
    expect(exit2.length).toBeGreaterThan(0);
    for (const { file, fx } of exit2) {
      expect(fx.observed.claudeSaw, file).toContain(fx.hookReply.stderr!);
      expect(fx.observed.claudeSaw, file).toMatch(/hook error: \[.+\]: /);
    }
    for (const { file, fx } of outputs.filter((o) => o.decision === "deny" && o.fx.scenario.replyMethod === "json")) {
      expect(fx.observed.claudeSaw, file).not.toMatch(/\[node |This hook comes from/);
    }
  });

  it("RT-PROTO-25: exit 2 blocks through a PowerShell-run hook too", () => {
    const ps = outputs.filter((o) => o.decision === "deny" && o.fx.scenario.replyMethod === "exit2" && o.fx.scenario.hookShell === "powershell");
    expect(ps.length).toBeGreaterThan(0);
    for (const { file, fx } of ps) expect(fx.observed.toolRan, file).toBe(false);
  });

  it("RT-PROTO-26: deny wins over acceptEdits plus an explicit allow rule", () => {
    const f = outputs.filter((o) => o.fx.scenario.run === "F" && o.decision === "deny");
    expect(f.length).toBe(2);
    for (const { file, fx } of f) {
      expect(fx.scenario.permissionMode, file).toBe("acceptEdits");
      expect(fx.observed.toolRan, file).toBe(false);
    }
  });
});

describe("fixture hygiene", () => {
  // Placeholders used by the sanitizer; anything else that looks like these is real data.
  const checks: [string, RegExp][] = [
    ["real UUID", /\b(?!00000000-0000-4000-8000-)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i],
    ["real tool_use id", /toolu_(?!FIXTURE)[A-Za-z0-9]{6,}/],
    ["user folder", /Users(\\\\|\/)(?!<user>)[^\\/"]+/],
    ["temp folder hash", /Temp(\\\\|\/)claude(\\\\|\/)(?!<hash>)[0-9a-f]{8,}/],
    ["e-mail address", /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}/],
    ["token", /\b(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_|eyJ[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[abp]-)/],
    ["private key", /BEGIN [A-Z ]*PRIVATE KEY/],
  ];

  it("RT-PROTO-27: no fixture contains identifying data or secrets", () => {
    for (const f of [...inputFiles, ...outputFiles]) {
      const text = fs.readFileSync(f, "utf8");
      for (const [name, re] of checks) expect(re.test(text), `${name} in ${rel(f)}`).toBe(false);
    }
  });

  it("the hygiene checks catch what they are meant to catch", () => {
    // Credential-shaped samples are built at run time so no tracked file contains one.
    const samples: Record<string, string> = {
      "real UUID": "62993619-fc2b-4680-a1d1-23d35f6f640c",
      "real tool_use id": "toolu_0111KakJ5nNhMp8w3hygXj5n",
      "user folder": "C:\\\\Users\\\\bob\\\\x",
      "temp folder hash": "Temp\\\\claude\\\\7694e029f887908a",
      "e-mail address": "someone@example.com",
      token: "gh" + "p_" + "a1".repeat(15),
      "private key": ["-----BEGIN", "OPENSSH", "PRIVATE", "KEY-----"].join(" "),
    };
    for (const [name, re] of checks) expect(re.test(samples[name]!), name).toBe(true);
  });
});
