// Public-source benchmark (bench/SOURCES.md): cases taken from published datasets and
// projects, stored as inert JSON in bench/public/. Nothing here executes a case: commands are
// strings passed to checkToolCall, which only analyzes them.
//
//   pnpm run bench:public            dev set (70%) only: per source/category report
//   pnpm run bench:public --final    the sealed holdout (30%), ONCE: refuses if FINAL.json exists
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ctx as baseCtx, winCtx as baseWinCtx } from "./lib.mjs";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const FINAL = process.argv.includes("--final");
const E = await import(new URL("../packages/engine/dist/index.js", import.meta.url).href);
const MODES = ["strict", "balanced", "autopilot"];

const finalPath = here("./public/FINAL.json");
if (FINAL && existsSync(finalPath)) {
  console.error("The sealed holdout has already been scored (bench/public/FINAL.json). It is scored once; a new holdout needs a new corpus version.");
  process.exit(1);
}
const file = FINAL ? "./public/holdout.json" : "./public/dev.json";
const CASES = JSON.parse(readFileSync(here(file), "utf8"));

function evaluate(c, mode) {
  if (c.kind === "manifest") {
    const r = E.analyzeServer(c.input.server);
    return { stopped: ["C", "D", "F"].includes(r.grade), passed: ["A", "B"].includes(r.grade), outcome: r.grade, findings: r.findings };
  }
  const cx = c.platform === "win32" ? baseWinCtx(mode, E.EMBEDDED_BASELINE) : baseCtx(mode, E.EMBEDDED_BASELINE);
  const d = c.kind === "result"
    ? E.checkToolResult({ call: { serverId: "web", toolName: "fetch_page", arguments: { url: "https://example.com/page" } }, result: { content: [{ type: "text", text: c.input.text }] } }, cx)
    : E.checkToolCall({ serverId: "builtin", toolName: c.input.tool, arguments: { command: c.input.command } }, cx);
  return { stopped: d.verdict === "ask" || d.verdict === "deny", passed: d.verdict === "allow" || d.verdict === "warn", outcome: d.verdict, findings: d.findings };
}

// label "stop": should be ask/deny (grade C/D/F); "warn": anything but allow (grade not A);
// "benign": should pass (allow/warn; grade A/B). Benign asks and denies are both reported.
function score(mode) {
  const groups = new Map();
  const misses = [], fps = [];
  for (const c of CASES) {
    const r = evaluate(c, mode);
    const key = `${c.kind === "manifest" ? "manifest" : c.kind === "result" ? "result" : "call"} · ${c.category}`;
    const g = groups.get(key) ?? { stopN: 0, stopHit: 0, warnN: 0, warnHit: 0, benN: 0, benPass: 0, benAsk: 0, benDeny: 0 };
    if (c.label === "stop") { g.stopN++; if (r.stopped) g.stopHit++; else misses.push({ c, r }); }
    else if (c.label === "warn") { g.warnN++; if (r.outcome !== "allow" && r.outcome !== "A") g.warnHit++; else misses.push({ c, r }); }
    else {
      g.benN++;
      if (r.passed) g.benPass++; else fps.push({ c, r });
      if (r.outcome === "ask") g.benAsk++;
      if (r.outcome === "deny" || r.outcome === "F" || r.outcome === "D") g.benDeny++;
    }
    groups.set(key, g);
  }
  return { groups, misses, fps };
}

const pct = (a, b) => (b === 0 ? "–" : `${((100 * a) / b).toFixed(1)}%`);
const brief = (c) => JSON.stringify(c.kind === "manifest" ? `${c.input.server.serverId}: ${c.input.server.tools[0]?.name} ${c.input.server.tools[0]?.description ?? ""}` : c.kind === "result" ? c.input.text : c.input.command).slice(0, 120);

const L = [];
const res = Object.fromEntries(MODES.map((m) => [m, score(m)]));
const head = FINAL ? "Sealed holdout (30%), scored once" : "Dev set (70%)";
L.push(`# Public-source benchmark: ${head}`, "", `${CASES.length} cases. Sources and labelling rules: bench/SOURCES.md.`, "");
L.push("## Balanced mode", "", "| surface · category | stop: caught | warn-group: flagged | benign: passed | benign asks | benign denies (or grade D/F) |", "|---|---|---|---|---|---|");
const tot = { stopN: 0, stopHit: 0, warnN: 0, warnHit: 0, benN: 0, benPass: 0, benAsk: 0, benDeny: 0 };
for (const [k, g] of [...res.balanced.groups].sort()) {
  for (const f of Object.keys(tot)) tot[f] += g[f];
  L.push(`| ${k} | ${g.stopHit}/${g.stopN} (${pct(g.stopHit, g.stopN)}) | ${g.warnHit}/${g.warnN} (${pct(g.warnHit, g.warnN)}) | ${g.benPass}/${g.benN} (${pct(g.benPass, g.benN)}) | ${g.benAsk} | ${g.benDeny} |`);
}
L.push(`| **all** | ${tot.stopHit}/${tot.stopN} (**${pct(tot.stopHit, tot.stopN)}**) | ${tot.warnHit}/${tot.warnN} (${pct(tot.warnHit, tot.warnN)}) | ${tot.benPass}/${tot.benN} (**${pct(tot.benPass, tot.benN)}**) | ${tot.benAsk} | ${tot.benDeny} |`);
const tp = tot.stopHit, fn = tot.stopN - tot.stopHit, fp = tot.benN - tot.benPass;
L.push("", `Recall (stop label) ${pct(tp, tp + fn)} · precision ${pct(tp, tp + fp)} · false-positive rate ${pct(fp, tot.benN)} (benign stopped: ask, deny or grade C/D/F).`, "");
L.push("## By mode (calls and results; stop label caught / benign stopped)", "", "| mode | stop caught | benign stopped |", "|---|---|---|");
for (const m of MODES) {
  let a = 0, an = 0, b = 0, bn = 0;
  for (const [k, g] of res[m].groups) if (!k.startsWith("manifest")) { a += g.stopHit; an += g.stopN; b += g.benN - g.benPass; bn += g.benN; }
  L.push(`| ${m} | ${a}/${an} (${pct(a, an)}) | ${b}/${bn} (${pct(b, bn)}) |`);
}
if (!FINAL) {
  L.push("", `## Misses (${res.balanced.misses.length})`, "", "| id | label | got | case |", "|---|---|---|---|");
  for (const { c, r } of res.balanced.misses) L.push(`| ${c.id} | ${c.label} | ${r.outcome} | ${brief(c).replace(/\|/g, "\\|")} |`);
  L.push("", `## Benign stopped (${res.balanced.fps.length})`, "", "| id | got | findings | case |", "|---|---|---|---|");
  for (const { c, r } of res.balanced.fps) L.push(`| ${c.id} | ${r.outcome} | ${[...new Set(r.findings.map((f) => f.ruleId))].join(" ") || "–"} | ${brief(c).replace(/\|/g, "\\|")} |`);
}
const md = L.join("\n") + "\n";
if (FINAL) {
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  writeFileSync(finalPath, JSON.stringify({ scoredAt: new Date().toISOString(), commit, engine: E.ENGINE_VERSION ?? null, cases: CASES.length, balanced: Object.fromEntries(res.balanced.groups), total: tot }, null, 2) + "\n");
  writeFileSync(here("./public/FINAL.md"), `Engine commit ${commit}.\n\n` + md);
} else {
  mkdirSync(here("./results"), { recursive: true });
  writeFileSync(here("./results/public-dev.md"), md);
}
console.log(md.split("\n## Misses")[0]);
