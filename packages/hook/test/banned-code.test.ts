// Lint bans for the hook (no network, no child processes) and for protocol (pure: no I/O).
// Each case is a red-team attempt to sneak the banned capability in.
import { ESLint } from "eslint";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const eslint = new ESLint({ cwd: repoRoot });

async function errorsFor(code: string, filePath: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath });
  return (result?.messages ?? []).filter((m) => m.severity === 2).map((m) => m.ruleId ?? "fatal");
}

const HOOK_FILE = "packages/hook/src/__probe__.ts";
const PROTOCOL_FILE = "packages/protocol/src/__probe__.ts";

const HOOK_MUST_FAIL: ReadonlyArray<readonly [string, string]> = [
  ["node:net", `import net from "node:net"; export const x = net;`],
  ["https", `import https from "https"; export const x = https;`],
  ["node:http", `import { request } from "node:http"; export const x = request;`],
  ["node:dns", `import dns from "node:dns"; export const x = dns;`],
  ["node:tls", `import tls from "node:tls"; export const x = tls;`],
  ["child_process", `import { spawn } from "node:child_process"; export const x = spawn;`],
  ["re-export of a banned module", `export { connect } from "node:net";`],
  ["fetch", `export const x = () => fetch("https://example.invalid");`],
  ["WebSocket", `export const x = () => new WebSocket("wss://example.invalid");`],
  ["dynamic import", `export const x = () => import("node:net");`],
  ["eval", `export const x = (s: string) => eval(s);`],
];

describe("hook source: no network, no child processes (RT-HOOK-21)", () => {
  it.each(HOOK_MUST_FAIL)("%s is rejected", async (_name, code) => {
    expect((await errorsFor(code, HOOK_FILE)).length).toBeGreaterThan(0);
  });

  it("an inline eslint-disable comment doesn't switch the ban off", async () => {
    expect(await errorsFor('/* eslint-disable */\nimport net from "node:net";\nexport const x = net;', HOOK_FILE)).toContain("no-restricted-imports");
  });

  it("ordinary hook code (fs, path, crypto) is allowed", async () => {
    const code = `import fs from "node:fs";\nimport path from "node:path";\nimport crypto from "node:crypto";\nexport const x = [fs, path, crypto];`;
    expect(await errorsFor(code, HOOK_FILE)).toEqual([]);
  });
});

describe("protocol source: pure, no I/O (RT-PROTO-30)", () => {
  it.each([
    ["node:fs", `import fs from "node:fs"; export const x = fs;`],
    ["fetch", `export const x = () => fetch("https://example.invalid");`],
    ["process.env", `export const x = process.env;`],
  ])("%s is rejected", async (_name, code) => {
    expect((await errorsFor(code, PROTOCOL_FILE)).length).toBeGreaterThan(0);
  });
});
