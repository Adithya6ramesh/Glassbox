// RT-S9 (end to end): with this workspace's pnpm settings, installing a dependency
// that has a build script FAILS, and the script never runs. Runs offline: the
// dependency is a local directory whose postinstall would write a marker file.
//
// Needs the pnpm that runs this test (`pnpm run test` sets npm_execpath). The test
// fails rather than skips when it's missing, so the guarantee can't be lost silently.
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../../", import.meta.url));
const dirs: string[] = [];

function pnpm(cwd: string, args: string[]) {
  const execPath = process.env["npm_execpath"];
  if (!execPath || !/pnpm/i.test(execPath)) {
    throw new Error("Run this test through pnpm (`pnpm run test`): npm_execpath must point at pnpm.");
  }
  const isScript = /\.(c|m)?js$/i.test(execPath);
  return spawnSync(isScript ? process.execPath : execPath, isScript ? [execPath, ...args] : args, {
    cwd,
    encoding: "utf8",
    timeout: 120_000,
    env: { ...process.env, COREPACK_ENABLE_DOWNLOAD_PROMPT: "0", CI: "true" },
  });
}

function makeProject(workspaceYaml: string) {
  const root = mkdtempSync(join(tmpdir(), "glassbox-buildscript-"));
  dirs.push(root);
  const dep = join(root, "evil-dep");
  mkdirSync(dep);
  writeFileSync(join(dep, "package.json"), JSON.stringify({
    name: "evil-dep",
    version: "1.0.0",
    scripts: { postinstall: "node -e \"require('fs').writeFileSync(require('path').join(__dirname,'..','PWNED'),'x')\"" },
  }));
  const app = join(root, "app");
  mkdirSync(app);
  writeFileSync(join(app, "package.json"), JSON.stringify({
    name: "app", version: "1.0.0", private: true,
    dependencies: { "evil-dep": "file:../evil-dep" },
  }));
  writeFileSync(join(app, "pnpm-workspace.yaml"), workspaceYaml);
  return { root, app };
}

// The repo's settings, minus the `packages:` list (the probe isn't a workspace).
const repoSettings = readFileSync(join(repoRoot, "pnpm-workspace.yaml"), "utf8")
  .replace(/^packages:\r?\n(\s+-.*\r?\n)*/m, "");

afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

describe("RT-S9: dependency build scripts", () => {
  it("an install with a build-script dependency fails, and the script does not run", () => {
    const { root, app } = makeProject(repoSettings);
    const r = pnpm(app, ["install", "--no-frozen-lockfile"]);
    expect(r.status, r.stdout + r.stderr).not.toBe(0);
    expect(r.stdout + r.stderr).toMatch(/ERR_PNPM_IGNORED_BUILDS|Ignored build scripts/);
    expect(existsSync(join(root, "PWNED"))).toBe(false);
  });

  it("control: the same project with ignoreScripts installs silently (why it's not used)", () => {
    const { root, app } = makeProject(repoSettings + "\nignoreScripts: true\n");
    const r = pnpm(app, ["install", "--no-frozen-lockfile"]);
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(existsSync(join(root, "PWNED"))).toBe(false);
  });
}, 300_000);
