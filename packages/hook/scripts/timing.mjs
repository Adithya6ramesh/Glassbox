// Hook timing: wall clock for one hook process, measured from the parent (spawn to exit),
// the way Claude Code experiences it. Reports p50/p95/p99/max for:
//   - node-empty: `node -e ""` (the floor: Node start-up on this machine)
//   - pre-allow:  PreToolUse that returns no decision (`echo hello`)
//   - pre-deny:   PreToolUse that denies (a write to Claude Code settings)
//   - post:       PostToolUse recording
// Two conditions:
//   - warm: the same installed files, run repeatedly (after a few discarded runs)
//   - cold: each run uses a fresh copy of the installed files, as right after an install or
//           update (new files: not in the OS file cache yet, scanned by antivirus on first
//           read). A cold boot is not reproducible here and is not claimed.
// Usage: node packages/hook/scripts/timing.mjs [--warm N] [--cold N] [--json out.json]
// The hook writes its state into a throwaway folder (--home), never into ~/.glassbox.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};
const WARM = Number(opt("--warm", "100"));
const COLD = Number(opt("--cold", "20"));
const JSON_OUT = opt("--json", "");
// --entry selects the start file under dist/ (main.js = unbundled, bundle/main.mjs = bundled).
const ENTRY = opt("--entry", "main.js");
// --file <path> times a standalone bundle (e.g. one downloaded from the hook-release workflow);
// cold runs copy just that file to a fresh folder.
const FILE = opt("--file", "");

const hookDir = fileURLToPath(new URL("..", import.meta.url));
const MAIN = FILE ? path.resolve(FILE) : path.join(hookDir, "dist", ENTRY);
if (!fs.existsSync(MAIN)) {
  console.error("Build first: pnpm run build");
  process.exit(1);
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), "gbx-hook-timing-"));
const home = path.join(work, "home");
const project = path.join(home, "proj");
fs.mkdirSync(project, { recursive: true });

let n = 0;
const base = () => ({ session_id: "00000000-0000-4000-8000-000000000001", transcript_path: "", cwd: project, permission_mode: "default", effort: { level: "medium" } });
const id = () => `toolu_TIMING${String(++n).padStart(12, "0")}`;
const payloads = {
  "pre-allow": () => ({ ...base(), hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "echo hello", description: "x" }, tool_use_id: id() }),
  "pre-deny": () => ({ ...base(), hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: path.join(home, ".claude", "settings.json"), content: "{}" }, tool_use_id: id() }),
  post: () => ({ ...base(), hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "echo hello", description: "x" }, tool_response: { stdout: "hello", stderr: "", interrupted: false, isImage: false }, tool_use_id: id(), duration_ms: 3 }),
};
const EVENT = { "pre-allow": "pre", "pre-deny": "pre", post: "post" };

function timeOnce(argv, input) {
  const t0 = process.hrtime.bigint();
  const r = spawnSync(process.execPath, argv, { input, encoding: "utf8", windowsHide: true });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const hint = FILE ? " (--file must be a self-contained bundle such as dist/bundle/main.mjs)" : "";
  if (r.status !== 0) throw new Error(`exit ${r.status}${hint}: ${r.stderr}`);
  return { ms, stdout: r.stdout };
}

// A self-contained copy of the installed hook: dist + the packages it imports.
// Node's lookup order: <dir>/node_modules/<name>, then each parent folder.
function pkgDir(name, from) {
  for (let dir = from; ; dir = path.dirname(dir)) {
    const cand = path.join(dir, "node_modules", ...name.split("/"));
    if (fs.existsSync(path.join(cand, "package.json"))) return fs.realpathSync(cand);
    if (path.dirname(dir) === dir) throw new Error(`can't find ${name} from ${from}`);
  }
}
// Only what an installed package ships: no sources, tests, corpus or nested node_modules.
const SKIP = /[\\/](src|test|bench|scripts|node_modules)$/;
function copyInstall(dest) {
  if (FILE) {
    const to = path.join(dest, path.basename(MAIN));
    fs.copyFileSync(MAIN, to);
    return to;
  }
  fs.cpSync(path.join(hookDir, "dist"), path.join(dest, "dist"), { recursive: true, dereference: true });
  fs.copyFileSync(path.join(hookDir, "package.json"), path.join(dest, "package.json"));
  const nm = path.join(dest, "node_modules");
  const engineDir = pkgDir("@glassbox-ai/engine", hookDir);
  const deps = new Map([
    ["@glassbox-ai/engine", engineDir],
    ["@glassbox-ai/protocol", pkgDir("@glassbox-ai/protocol", hookDir)],
    ["valibot", pkgDir("valibot", hookDir)],
    ["@noble/curves", pkgDir("@noble/curves", engineDir)],
    ["@noble/hashes", pkgDir("@noble/hashes", engineDir)],
    ["re2js", pkgDir("re2js", engineDir)],
  ]);
  for (const [name, dir] of deps) {
    const to = path.join(nm, ...name.split("/"));
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.cpSync(dir, to, { recursive: true, dereference: true, filter: (s) => s === dir || !SKIP.test(s) });
  }
  return path.join(dest, "dist", ENTRY);
}

const pct = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))];
function stats(samples) {
  const s = [...samples].sort((a, b) => a - b);
  return { n: s.length, p50: pct(s, 50), p95: pct(s, 95), p99: pct(s, 99), max: s[s.length - 1] };
}

// Sanity: the scenarios do what their names say.
const allow = timeOnce([MAIN, "pre", "--home", home], JSON.stringify(payloads["pre-allow"]()));
const deny = timeOnce([MAIN, "pre", "--home", home], JSON.stringify(payloads["pre-deny"]()));
if (allow.stdout !== "" || !deny.stdout.includes("\"deny\"")) throw new Error("scenario check failed");

const results = {};
// Warm.
for (let i = 0; i < 5; i++) timeOnce(["-e", ""], "");
results["warm node-empty"] = stats(Array.from({ length: WARM }, () => timeOnce(["-e", ""], "").ms));
for (const name of Object.keys(payloads)) {
  for (let i = 0; i < 5; i++) timeOnce([MAIN, EVENT[name], "--home", home], JSON.stringify(payloads[name]()));
  results[`warm ${name}`] = stats(Array.from({ length: WARM }, () => timeOnce([MAIN, EVENT[name], "--home", home], JSON.stringify(payloads[name]())).ms));
}
// Cold: a fresh copy of the install for every sample.
for (const name of COLD > 0 ? ["pre-allow", "pre-deny"] : []) {
  const samples = [];
  for (let i = 0; i < COLD; i++) {
    const main = copyInstall(fs.mkdtempSync(path.join(work, "install-")));
    samples.push(timeOnce([main, EVENT[name], "--home", home], JSON.stringify(payloads[name]())).ms);
  }
  results[`cold ${name}`] = stats(samples);
}

const env = { platform: process.platform, arch: process.arch, node: process.version, cpus: os.cpus().length, cpu: os.cpus()[0]?.model ?? "?" };
const f = (x) => x.toFixed(1);
const lines = [
  `Hook timing via ${FILE ? path.basename(MAIN) + " (standalone)" : ENTRY} (ms, wall clock per hook process, parent-measured) on ${env.platform}/${env.arch}, Node ${env.node}, ${env.cpus}× ${env.cpu}`,
  "",
  "| scenario | n | p50 | p95 | p99 | max |",
  "|---|---|---|---|---|---|",
  ...Object.entries(results).map(([k, s]) => `| ${k} | ${s.n} | ${f(s.p50)} | ${f(s.p95)} | ${f(s.p99)} | ${f(s.max)} |`),
  "",
  "Target: p95 ≤ 150 ms for an allow (warm), including Node start-up. Not gated: runners vary.",
];
console.log(lines.join("\n"));
if (JSON_OUT) fs.writeFileSync(JSON_OUT, JSON.stringify({ env, results }, null, 2));
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join("\n") + "\n");
fs.rmSync(work, { recursive: true, force: true });
