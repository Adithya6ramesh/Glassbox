// Self-protection and sensitive paths, built-in tool profiles.
import { describe, expect, it } from "vitest";
import { builtin, ctx, MODES, ps, ruleIds, winCtx } from "../helpers.js";

describe("protected writes via file tools", () => {
  it.each([
    "/home/u/.claude/settings.json",
    "/home/u/.claude/settings.local.json",
    "/home/u/.claude.json",
    "/home/u/.claude/hooks/pre.sh",
    "/home/u/.claude/plugins/cache/glassbox/hooks.json",
    "/home/u/proj/.claude/settings.json",
    "/home/u/proj/.mcp.json",
    "/home/u/.claude/../.claude/settings.json",
    "/home/u//.claude/./settings.json",
    "/home/u/.glassbox/config.json",
    "/home/u/.glassbox/rules/ruleset.json",
    "/etc/claude-code/managed-settings.json",
    "/etc/claude-code/managed-settings.d/10-x.json",
    "/Library/Application Support/ClaudeCode/managed-mcp.json",
    "/somewhere/else/.claude/settings.json",
    "~/.claude/settings.json",
    ".mcp.json",
    "../proj/.claude/settings.local.json",
  ])("Write %s → deny", (path) => {
    const d = builtin("Write", { file_path: path, content: "{}" });
    expect(d.actionRisk.selfProtection).toBe(true);
    expect(d.verdict).toBe("deny");
    expect(ruleIds(d)).toContain("CP-SELF-001");
  });

  it("the effective CLAUDE_CONFIG_DIR and ~/.claude are both protected", () => {
    const c = ctx({ claudeConfigDir: "/opt/claude-cfg" });
    expect(builtin("Write", { file_path: "/opt/claude-cfg/settings.json", content: "" }, c).verdict).toBe("deny");
    expect(builtin("Write", { file_path: "/home/u/.claude/settings.json", content: "" }, c).verdict).toBe("deny");
  });

  it("extraProtectedPaths add to the set", () => {
    const c = ctx({ policy: { mode: "balanced", extraProtectedPaths: ["/home/u/secrets/**"] } });
    expect(builtin("Write", { file_path: "/home/u/secrets/a.txt", content: "" }, c).verdict).toBe("deny");
  });

  it("ordinary project writes are allowed", () => {
    for (const p of ["/home/u/proj/src/index.ts", "src/a.ts", "/home/u/proj/settings.json"]) {
      const d = builtin("Write", { file_path: p, content: "x" });
      expect(d.actionRisk.selfProtection, p).toBe(false);
      expect(d.verdict, p).toBe("allow");
    }
  });

  // Owner decision 2026-11-25 (spec rev 11b, Q-112-1): .claude/agents was an "ordinary write"
  // above; it is now agent config. Still not self-protection (not denied), but it asks.
  it(".claude/agents is agent config: not self-protection, but a liftable ask", () => {
    const d = builtin("Write", { file_path: "/home/u/proj/.claude/agents/x.md", content: "x" });
    expect(d.actionRisk.selfProtection).toBe(false);
    expect(d.actionRisk.tags).toContain("config.agent");
    expect(d.verdict).toBe("ask");
  });

  it("caller-resolved realpaths are checked too", () => {
    const c = ctx({ resolvedPaths: { "/home/u/proj/link.json": "/home/u/.claude/settings.json" } });
    expect(builtin("Write", { file_path: "/home/u/proj/link.json", content: "" }, c).verdict).toBe("deny");
  });
});

describe("Windows normalization", () => {
  const W = (p: string) => builtin("Write", { file_path: p, content: "" }, winCtx());
  it.each([
    "C:\\Users\\u\\.claude\\settings.json",
    "c:/users/U/.CLAUDE/Settings.json",
    "\\\\?\\C:\\Users\\u\\.claude\\settings.json",
    "\\\\localhost\\c$\\Users\\u\\.claude\\settings.json",
    "C:\\Users\\u\\.claude\\settings.json.",
    "C:\\Users\\u\\.claude\\settings.json::$DATA",
    "C:\\Users\\u\\.claude \\settings.json",
    "%USERPROFILE%\\.claude\\settings.json",
    "$env:USERPROFILE\\.claude\\settings.json",
    "C:\\Program Files\\ClaudeCode\\managed-settings.json",
    "C:\\ProgramData\\ClaudeCode\\managed-settings.json",
    "C:\\Users\\u\\.glassbox\\config.json",
  ])("%s → deny", (p) => {
    expect(W(p).verdict).toBe("deny");
  });

  it("8.3 short names that could match a protected path → deny (Q8)", () => {
    expect(W("C:\\Users\\u\\CLAUDE~1\\settings.json").verdict).toBe("deny");
    expect(W("C:\\Users\\u\\GLASSB~1\\config.json").verdict).toBe("deny");
  });

  it("ordinary Windows project writes are allowed", () => {
    expect(W("C:\\Users\\u\\proj\\src\\index.ts").verdict).toBe("allow");
  });
});

describe("protected reads (I14)", () => {
  it.each([
    ["Read", { file_path: "/home/u/.glassbox/device.key" }],
    ["Read", { file_path: "~/.glassbox/device.key" }],
    ["Read", { file_path: "/home/u/.glassbox/keys/upload.key" }],
    ["Grep", { pattern: ".", path: "/home/u/.glassbox" }],
    ["Grep", { pattern: "x", path: "/home/u" }],
    ["Glob", { pattern: "**/*.key", path: "/home/u/.glassbox" }],
    ["Glob", { pattern: "/home/u/.glassbox/**" }],
  ])("%s %j → deny", (tool, args) => {
    const d = builtin(tool, args);
    expect(d.actionRisk.selfProtection).toBe(true);
    expect(d.verdict).toBe("deny");
  });

  it("glassboxSecretPaths are read-protected", () => {
    const c = ctx({ glassboxSecretPaths: ["/home/u/.config/gbx/token"] });
    expect(builtin("Read", { file_path: "/home/u/.config/gbx/token" }, c).verdict).toBe("deny");
  });

  it("PowerShell reads of device.key → deny", () => {
    expect(ps("Get-Content $env:USERPROFILE\\.glassbox\\device.key").verdict).toBe("deny");
    expect(ps("gc ~\\.glassbox\\device.key").verdict).toBe("deny");
  });

  it("Grep in the project is fine", () => {
    expect(builtin("Grep", { pattern: "TODO", path: "/home/u/proj/src" }).verdict).toBe("allow");
  });
});

describe("sensitive reads", () => {
  it.each([
    "/home/u/.ssh/id_rsa",
    "/home/u/.aws/credentials",
    "/home/u/proj/.env",
    "/home/u/proj/.env.production",
    "/home/u/proj/certs/server.pem",
    "/home/u/.netrc",
    "/home/u/.kube/config",
  ])("Read %s → CP-EXFIL-040 warn + sensitive-read signal", (p) => {
    const d = builtin("Read", { file_path: p });
    expect(ruleIds(d)).toContain("CP-EXFIL-040");
    expect(d.actionRisk.tags).toContain("fs.read.sensitive");
    expect(d.verdict).toBe("warn");
    expect(d.signals.some((s) => s.kind === "sensitive-read")).toBe(true);
  });

  it(".env.example is not sensitive", () => {
    const d = builtin("Read", { file_path: "/home/u/proj/.env.example" });
    expect(ruleIds(d)).not.toContain("CP-EXFIL-040");
    expect(d.verdict).toBe("allow");
  });
});

describe("built-in tool profiles", () => {
  it("read tools allow", () => {
    for (const t of ["Read", "Glob", "Grep", "LS", "WebSearch", "TodoWrite", "AskUserQuestion"]) {
      expect(builtin(t, { file_path: "/home/u/proj/a", pattern: "x", query: "q" }).actionRisk.level, t).toBe("read");
    }
  });

  it("WebFetch is high-risk net.egress, records only the host, warns in balanced", () => {
    const d = builtin("WebFetch", { url: "https://docs.example.com/path/secret?token=abc", prompt: "summarize" });
    expect(d.actionRisk.level).toBe("high-risk");
    expect(d.actionRisk.tags).toContain("net.egress");
    expect(d.actionRisk.reasons.join(" ")).toContain("docs.example.com");
    expect(d.actionRisk.reasons.join(" ")).not.toContain("token=abc");
    expect(d.actionRisk.reasons.join(" ")).not.toContain("/path/secret");
    expect(d.verdict).toBe("warn");
  });

  it("Agent / Task / Skill / Workflow start agent work: write-reversible, allowed", () => {
    for (const t of ["Agent", "Task", "Skill", "Workflow"]) {
      const d = builtin(t, { prompt: "x" });
      expect(d.actionRisk.level, t).toBe("write-reversible");
      expect(d.actionRisk.unanalyzable, t).toBe(false);
      expect(d.verdict, t).toBe("allow");
    }
  });

  it("an unknown built-in tool is unanalyzable: ask in strict and balanced, deny in autopilot", () => {
    for (const t of ["SomeFutureTool", "RunScript"]) {
      const r = builtin(t, { prompt: "x" }).actionRisk;
      expect(r.unanalyzable, t).toBe(true);
      expect(MODES.map((mode) => builtin(t, { prompt: "x" }, ctx({ policy: { mode } })).verdict), t).toEqual(["ask", "ask", "deny"]);
    }
  });
});
