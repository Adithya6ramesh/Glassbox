// Runs a command under real bash and records the argv of every command bash executes,
// without running any real program:
// - PATH points at an empty directory, so every external command falls through to
//   command_not_found_handle, which only logs its argv;
// - echo, printf, true, false, test, [, pwd, kill and read are replaced by logging functions;
// - HOME and the working directory are a fresh sandbox directory.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PREAMBLE = String.raw`
exec 9>>"$GBX_LOG"
__gbx_log() { local a; printf '%s\0' "$#" >&9; for a in "$@"; do printf '%s\0' "$a" >&9; done; }
command_not_found_handle() { __gbx_log "$@"; return 0; }
echo() { __gbx_log echo "$@"; }
printf() { __gbx_log printf "$@"; }
true() { __gbx_log true "$@"; return 0; }
false() { __gbx_log false "$@"; return 1; }
test() { __gbx_log test "$@"; return 1; }
[() { __gbx_log [ "$@"; return 1; }
pwd() { __gbx_log pwd "$@"; }
kill() { __gbx_log kill "$@"; }
read() { __gbx_log read "$@"; return 1; }
type() { __gbx_log type "$@"; }
hash() { __gbx_log hash "$@"; }
`;

export interface BashRun {
  /** argv of every command bash executed (logged), in order. */
  executed: string[][];
  syntaxError: boolean;
  timedOut: boolean;
}

export function findBash(): string | undefined {
  const fromEnv = process.env["GLASSBOX_BASH"];
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  if (process.platform === "linux" || process.platform === "darwin") return "/bin/bash";
  return undefined;
}

function parseLog(buf: Buffer): string[][] {
  const parts = buf.toString("utf8").split("\0");
  const out: string[][] = [];
  let i = 0;
  while (i < parts.length - 1) {
    const n = Number(parts[i++]);
    if (!Number.isInteger(n) || n < 0) break;
    out.push(parts.slice(i, i + n));
    i += n;
  }
  return out;
}

export function runInBash(bash: string, command: string, timeoutMs = 4000): Promise<BashRun> {
  const root = mkdtempSync(join(tmpdir(), "gbx-difftest-"));
  const sandbox = join(root, "sandbox");
  const emptyPath = join(root, "empty-path");
  mkdirSync(sandbox);
  mkdirSync(emptyPath);
  const log = join(root, "log.bin");
  writeFileSync(log, "");
  const script = join(root, "cmd.sh");
  writeFileSync(script, PREAMBLE + "\n" + command + "\n");
  return new Promise((resolve) => {
    const child = spawn(bash, ["--norc", "--noprofile", script], {
      cwd: sandbox,
      env: { PATH: emptyPath, HOME: sandbox, GBX_LOG: log, LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
      stdio: ["ignore", "ignore", "pipe"],
      windowsHide: true,
    });
    let stderr = "";
    let timedOut = false;
    child.stderr.on("data", (d: Buffer) => { if (stderr.length < 4096) stderr += d.toString("utf8"); });
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutMs);
    child.on("close", () => {
      clearTimeout(timer);
      let executed: string[][] = [];
      try { executed = parseLog(readFileSync(log)); } catch { /* no log */ }
      try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
      resolve({ executed, timedOut, syntaxError: /syntax error|unexpected EOF|unexpected end of file/i.test(stderr) });
    });
  });
}

/**
 * Does the parser's view contain a command matching `argv`? Parser words that are null
 * (unknown statically) match zero or more actual words.
 */
export function viewCovers(view: ReadonlyArray<ReadonlyArray<string | null>>, argv: readonly string[]): boolean {
  return view.some((cmd) => matches(cmd, argv));
}

function matches(pattern: ReadonlyArray<string | null>, argv: readonly string[]): boolean {
  // dp[i][j]: pattern[0..i) matches argv[0..j)
  const m = pattern.length, n = argv.length;
  let prev = new Array<boolean>(n + 1).fill(false);
  prev[0] = true;
  for (let i = 1; i <= m; i++) {
    const cur = new Array<boolean>(n + 1).fill(false);
    const p = pattern[i - 1];
    for (let j = 0; j <= n; j++) {
      if (p === null) cur[j] = prev[j]! || (j > 0 && cur[j - 1]!);
      else cur[j] = j > 0 && prev[j - 1]! && argv[j - 1] === p;
    }
    prev = cur;
  }
  return prev[n]!;
}
