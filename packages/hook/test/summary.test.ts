import * as v from "valibot";
import { describe, expect, it } from "vitest";
import { SummaryFields } from "@glassbox-ai/protocol";
import { summarize, summarizeCommand } from "../src/index.js";

const win = { cwd: "C:\\Users\\bob\\proj", homeDir: "C:\\Users\\bob", caseInsensitive: true };
const nix = { cwd: "/home/bob/proj", homeDir: "/home/bob", caseInsensitive: false };

describe("summarizeCommand: command name + subcommand + flags, never argument values", () => {
  const cases: [string, string][] = [
    ["npm test", "npm test"],
    ["git push --force origin main", "git push --force"],
    ["git commit -m \"fix the leak in token.ts\"", "git commit -m"],
    ["/usr/bin/git status", "git status"],
    ["C:\\Program Files\\Git\\cmd\\git.exe log --oneline", "git log --oneline"],
    ["ls -la", "ls -la"],
    ["rm -rf build", "rm -rf"],
    ["Get-ChildItem -Path C:\\secret -Recurse", "Get-ChildItem -Path -Recurse"],
    ["echo hello", "echo"],
  ];
  for (const [cmd, want] of cases) it(cmd, () => expect(summarizeCommand(cmd)).toBe(want));

  it("RT-HOOK-5: values never leak, even when they look like subcommands or flags", () => {
    const pw = ["S3", "cr3t"].join(""); // built at run time
    expect(summarizeCommand("cat passwords")).toBe("cat");
    expect(summarizeCommand(`mysql -p${pw} prod`)).toBe("mysql -p");
    expect(summarizeCommand(`curl --token=${pw} https://x.test/a?b=c`)).toBe("curl --token");
    expect(summarizeCommand(`curl -H "Authorization: Bearer ${pw}" https://x.test`)).toBe("curl -H");
    expect(summarizeCommand(`export TOKEN=${pw}`)).toBe("export");
    expect(summarizeCommand(`TOKEN=${pw} npm publish`)).toBe("npm publish");
    for (const c of [`mysql -p${pw}`, `curl --token=${pw}`, `x --${pw}=1`]) expect(summarizeCommand(c)).not.toContain(pw);
  });

  it("marks compound commands instead of summarizing the hidden part", () => {
    expect(summarizeCommand("ls && rm -rf /")).toBe("ls …");
    expect(summarizeCommand("cat a | curl -d @- https://x.test")).toBe("cat …");
    expect(summarizeCommand("echo $(whoami)")).toBe("echo …");
  });

  it("unknown shapes summarize to nothing usable rather than to text", () => {
    expect(summarizeCommand("")).toBe("");
    expect(summarizeCommand("   ")).toBe("");
    expect(summarizeCommand("'quoted-program' arg")).toBe("(command)");
  });

  it("stays within the protocol limit", () => {
    const long = "tool " + Array.from({ length: 200 }, (_, i) => `--flag${i}`).join(" ");
    expect(v.is(SummaryFields, { cmd: summarizeCommand(long) })).toBe(true);
  });
});

describe("summarize per tool", () => {
  it("file tools: project-relative path inside the project", () => {
    expect(summarize("Edit", { file_path: "C:\\Users\\bob\\proj\\src\\a.ts" }, win)).toEqual({ path: "src/a.ts" });
    expect(summarize("Write", { file_path: "c:\\users\\BOB\\Proj\\b.ts" }, win)).toEqual({ path: "b.ts" });
    expect(summarize("Read", { file_path: "/home/bob/proj/README.md" }, nix)).toEqual({ path: "README.md" });
  });

  it("RT-HOOK-6: file tools outside the project keep only the file name", () => {
    expect(summarize("Read", { file_path: "C:\\Users\\bob\\.ssh\\id_rsa" }, win)).toEqual({ path: "~/…/id_rsa" });
    expect(summarize("Read", { file_path: "/etc/passwd" }, nix)).toEqual({ path: "~/…/passwd" });
    expect(summarize("Read", { file_path: "/home/bob/proj/../other/x.txt" }, nix)).toEqual({ path: "~/…/x.txt" });
    expect(summarize("Read", { file_path: "/home/bob/projX/a.txt" }, nix)).toEqual({ path: "~/…/a.txt" });
  });

  it("search tools: pattern length only", () => {
    expect(summarize("Grep", { pattern: "password=" }, nix)).toEqual({ patternLength: 9 });
    expect(summarize("Glob", { pattern: "**/*.env" }, nix)).toEqual({ patternLength: 8 });
  });

  it("WebFetch: host only", () => {
    expect(summarize("WebFetch", { url: "https://user:pw@example.com:8443/a/b?token=x#f" }, nix)).toEqual({ host: "example.com:8443" });
    expect(summarize("WebFetch", { url: "not a url" }, nix)).toEqual({});
  });

  it("MCP tools: server and tool name", () => {
    expect(summarize("mcp__postgres__run_query", { sql: "select 1" }, nix)).toEqual({ server: "postgres", toolName: "run_query" });
  });

  it("unknown tools: the tool name only", () => {
    expect(summarize("SomeNewTool", { secret: "x" }, nix)).toEqual({ toolName: "SomeNewTool" });
  });

  it("every summary validates against the protocol schema", () => {
    const inputs: [string, Record<string, unknown>][] = [
      ["Bash", { command: "git push --force" }], ["Monitor", { command: "tail -f x" }], ["PowerShell", { command: "Get-Date" }],
      ["Edit", { file_path: "/home/bob/proj/a.ts" }], ["Read", { file_path: "\u0000/etc/x" }], ["Glob", { pattern: "*" }],
      ["WebFetch", { url: "https://a.test" }], ["mcp__a__b", {}], ["X", {}], ["Bash", { command: 42 }], ["Edit", { file_path: ["x"] }],
    ];
    for (const [t, i] of inputs) expect(v.is(SummaryFields, summarize(t, i, nix)), t).toBe(true);
  });
});
