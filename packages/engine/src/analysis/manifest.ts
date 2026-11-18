// analyzeServer (engine-spec §4.2, grading.md): metadata-only analysis of an MCP manifest.
import { buildViews } from "../canon/views.js";
import { profileMcpTool, nameWords } from "../action/tools.js";
import { fingerprintOf } from "../fingerprint/fingerprint.js";
import { scoreFindings } from "../grade/score.js";
import { resolveLimits } from "../limits.js";
import { EMBEDDED_BASELINE } from "../ruleset/baseline.js";
import type { ActionRisk, AnalyzeOptions, Finding, LoadedRuleset, RuleDef, ServerReport, ToolDef } from "../types.js";
import { get, getString, isRecord, utf8Length } from "../util/misc.js";
import { ENGINE_VERSION } from "../version.js";
import { manifestFields, type Field } from "./fields.js";
import { dedupe, FindingFactory, sortFindings } from "./findings.js";
import { matchRule, scanField, tokenize } from "./match.js";
import { intake } from "./gate.js";
import { scanFields } from "./scan.js";

const BUILTIN_TOOL_NAMES = ["Bash", "PowerShell", "Write", "Edit", "MultiEdit", "Read", "WebFetch", "WebSearch", "Grep", "Glob", "Agent", "Task", "NotebookEdit"];
const DIRECTIVE_WORDS = new Set(["instead", "always", "before", "after", "deprecated", "must", "never", "don't", "dont", "should", "replace", "override", "first"]);
const PURPOSE_HARMLESS = new Set(["time", "date", "clock", "timezone", "math", "calculate", "calculator", "add", "sum", "multiply", "convert", "format", "weather", "forecast", "random", "uuid", "echo", "ping", "joke", "quote", "temperature", "unit", "units", "color", "colour"]);
const CAP_PARAMS: [RegExp, string][] = [
  [/^(command|cmd|shell|script|code|exec|eval|bash|powershell)$/i, "exec"],
  [/^(path|file|filename|file_path|filepath|dir|directory)$/i, "path"],
  [/^(url|uri|endpoint|webhook|callback|callback_url)$/i, "url"],
  [/^(token|password|passwd|secret|api_?key|apikey|credential|credentials|private_?key|auth)$/i, "credentials"],
];

function editDistance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0] as number;
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j] as number;
      prev[j] = Math.min((prev[j] as number) + 1, (prev[j - 1] as number) + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length] as number;
}

/** Strings of one tool in document order, for split-payload detection. */
function toolStrings(tool: unknown, base: string): { pointer: string; text: string }[] {
  const out: { pointer: string; text: string }[] = [];
  const stack: { v: unknown; p: string }[] = [{ v: tool, p: base }];
  while (stack.length > 0 && out.length < 500) {
    const { v, p } = stack.shift() as { v: unknown; p: string };
    if (typeof v === "string") { if (!p.endsWith("/name") && !p.endsWith("/type")) out.push({ pointer: p, text: v }); }
    else if (Array.isArray(v)) v.forEach((x, i) => stack.push({ v: x, p: `${p}/${i}` }));
    else if (isRecord(v)) for (const k of Object.keys(v)) stack.push({ v: v[k], p: `${p}/${k.replace(/~/g, "~0").replace(/\//g, "~1")}` });
  }
  return out;
}

export function analyzeServerImpl(manifestIn: unknown, opts: AnalyzeOptions | undefined, t0: number): ServerReport {
  const limits = resolveLimits(opts?.limits);
  const ruleset: LoadedRuleset = opts?.ruleset && Array.isArray(opts.ruleset.rules) ? opts.ruleset : EMBEDDED_BASELINE;
  const ff = new FindingFactory(ruleset, opts?.evidenceMode === "none" ? "none" : "snippet");
  const findings: (Finding | null)[] = [];
  const degradedReasons: string[] = [];
  const ink = intake(manifestIn, limits);
  for (const i of ink.issues) findings.push(ff.make({ ruleId: i.code, location: i.pointer ?? "" }));
  if (ink.degraded) degradedReasons.push(...new Set(ink.issues.map((i) => i.code)));
  const m = isRecord(ink.value) ? ink.value : Object.create(null) as Record<string, unknown>;
  if (!isRecord(ink.value) && !ink.tooBig) findings.push(ff.make({ ruleId: "CP-PARSE-010", location: "" }));
  const toolsRaw = Array.isArray(get(m, "tools")) ? (get(m, "tools") as unknown[]) : [];
  let partial = ink.degraded;
  if (toolsRaw.length > limits.maxTools) {
    partial = true;
    degradedReasons.push("CP-LIMIT-004");
    findings.push(ff.make({ ruleId: "CP-LIMIT-004", location: "/tools" }));
  }
  const tools = toolsRaw.slice(0, limits.maxTools);

  // Layer 1 over every field.
  const fields: Field[] = manifestFields(m, limits.maxTools);
  const scan = scanFields(fields, "manifest", ff, ruleset.rules, limits, true);
  findings.push(...scan.findings);
  if (scan.windowed) { partial = true; degradedReasons.push("CP-LIMIT-006"); }
  if (scan.decodeExhausted) { degradedReasons.push("CP-LIMIT-007"); findings.push(ff.make({ ruleId: "CP-LIMIT-007", location: "" })); }

  // Per-field structural rules.
  for (const f of fields) {
    if (f.role === "tool.schema.enum" || f.role === "tool.schema.default" || f.role === "tool.schema.const" || f.role === "tool.schema.examples") {
      const words = tokenize(f.text);
      if (words.length >= 6 || (words.length >= 3 && /[.!?]\s*\S/.test(f.text.slice(0, 2000)))) findings.push(ff.make({ ruleId: "CP-POISON-020", location: f.pointer, text: f.text }));
    }
    if (f.role === "tool.schema.key" && (f.text.length > 40 || tokenize(f.text.replace(/_/g, " ")).length >= 5)) findings.push(ff.make({ ruleId: "CP-POISON-021", location: f.pointer, text: f.text }));
    if (f.role === "tool.description" && utf8Length(f.text) > limits.maxDescriptionBytes) findings.push(ff.make({ ruleId: "CP-LIMIT-005", location: f.pointer, text: f.text.slice(0, 200) }));
  }

  // Per tool.
  const names = new Map<string, number>();
  const ownNames = new Set(tools.map((t) => getString(t, "name") ?? ""));
  const known = (opts?.knownTools ?? []).filter((k) => isRecord(k) && typeof k.name === "string");
  const capabilityProfile: { tool: string; risk: ActionRisk }[] = [];
  const poisonRules = ruleset.rules.filter((r) => ["CP-POISON-001", "CP-POISON-002", "CP-POISON-003"].includes(r.id)) as RuleDef[];
  tools.forEach((t, i) => {
    const base = `/tools/${i}`;
    const name = getString(t, "name");
    const desc = getString(t, "description");
    if (name === undefined) { findings.push(ff.make({ ruleId: "CP-PARSE-010", location: `${base}/name` })); return; }
    names.set(name, (names.get(name) ?? 0) + 1);
    if (names.get(name) === 2) findings.push(ff.make({ ruleId: "CP-PARSE-004", location: `${base}/name`, text: name }));
    if (!desc || desc.trim().length === 0) findings.push(ff.make({ ruleId: "CP-HYGIENE-001", location: base, text: name }));
    if (!isRecord(get(t, "inputSchema"))) findings.push(ff.make({ ruleId: "CP-HYGIENE-003", location: base, text: name }));
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(name)) findings.push(ff.make({ ruleId: "CP-HYGIENE-004", location: `${base}/name`, text: name }));
    const prof = profileMcpTool(name, t as ToolDef);
    const ann = get(t, "annotations");
    if (prof.acc.level === "high-risk" && !isRecord(ann)) findings.push(ff.make({ ruleId: "CP-HYGIENE-002", location: base, text: name }));
    if (prof.contradiction) findings.push(ff.make({ ruleId: "CP-CAP-002", location: `${base}/annotations`, text: name }));
    capabilityProfile.push({ tool: name, risk: { level: prof.acc.level, tags: [...prof.acc.tags].sort(), unanalyzable: false, selfProtection: false, reasons: ["what the metadata says the tool can do"] } });

    // Capability mismatch: a harmless-sounding purpose asking for powerful inputs.
    const purpose = [...nameWords(name), ...nameWords((desc ?? "").split(/[.\n]/)[0] ?? "").slice(0, 6)];
    const harmless = purpose.some((w) => PURPOSE_HARMLESS.has(w)) && prof.acc.level !== "high-risk";
    const props = get(get(t, "inputSchema"), "properties");
    if (harmless && isRecord(props)) {
      for (const k of Object.keys(props)) {
        const cap = CAP_PARAMS.find(([re]) => re.test(k));
        if (cap) { findings.push(ff.make({ ruleId: "CP-CAP-001", location: `${base}/inputSchema/properties/${k.replace(/~/g, "~0").replace(/\//g, "~1")}`, text: k })); break; }
      }
    }

    // Split payload: instruction phrases that only appear across fields.
    const strs = toolStrings(t, base);
    // Top-level text fields (title, description, …) together, then every string of the tool.
    const top = strs.filter((x) => x.pointer.split("/").length === 4);
    for (const group of [top, strs]) {
      if (group.length < 2) continue;
      const joined = group.map((x) => x.text).join(" ");
      const scanJ = scanField(joined, limits.maxFieldScanBytes, { bytes: 0 }, 0);
      let reported = false;
      for (const r of poisonRules) {
        if (!matchRule(r, scanJ, undefined)) continue;
        const single = group.some((x) => matchRule(r, scanField(x.text, limits.maxFieldScanBytes, { bytes: 0 }, 0), undefined));
        if (!single) { findings.push(ff.make({ ruleId: "CP-POISON-030", location: base, text: joined, via: ["concat"], related: group.map((x) => x.pointer).slice(0, 10) })); reported = true; break; }
      }
      if (reported) break;
    }

    // Shadowing: directives about a tool that isn't on this server.
    for (const s of strs) {
      const words = tokenize(s.text.slice(0, limits.maxFieldScanBytes));
      const lower = new Set(words.map((w) => w.w.toLowerCase()));
      if (![...DIRECTIVE_WORDS].some((d) => lower.has(d))) continue;
      const otherNames = new Set([...known.map((k) => k.name), ...BUILTIN_TOOL_NAMES].filter((n) => !ownNames.has(n)));
      let hit: string | null = null;
      for (const n of otherNames) {
        const isBuiltin = BUILTIN_TOOL_NAMES.includes(n);
        const idx = s.text.indexOf(n);
        if (idx < 0) continue;
        const after = s.text.slice(idx + n.length, idx + n.length + 6).toLowerCase();
        const beforeCh = s.text[idx - 1] ?? " ";
        const boundary = !/[A-Za-z0-9_]/.test(beforeCh) && !/^[A-Za-z0-9_]/.test(s.text.slice(idx + n.length, idx + n.length + 1));
        if (!boundary) continue;
        if (isBuiltin && !(after.startsWith(" tool") || after.startsWith("`") || after.startsWith("(") || beforeCh === "`")) continue;
        hit = n;
        break;
      }
      if (hit) { findings.push(ff.make({ ruleId: "CP-SHADOW-001", location: s.pointer, text: s.text, start: s.text.indexOf(hit), end: s.text.indexOf(hit) + hit.length })); break; }
    }

    // Collisions and typosquats against other servers' tools.
    for (const k of known) {
      if (k.name === name) { findings.push(ff.make({ ruleId: "CP-SHADOW-010", location: `${base}/name`, text: name })); break; }
      const skelA = buildViews(name).skeleton.text, skelB = buildViews(k.name).skeleton.text;
      if (name.length >= 5 && (skelA === skelB || editDistance(name.toLowerCase(), k.name.toLowerCase()) <= 2)) {
        findings.push(ff.make({ ruleId: "CP-SHADOW-010", location: `${base}/name`, text: name }));
        break;
      }
    }
  });

  // Session id shape (caller-reported).
  const sid = opts?.sessionIdShape;
  if (sid && isRecord(sid) && (sid.length < 16 || sid.sequentialSuspected || sid.charset === "digits")) findings.push(ff.make({ ruleId: "CP-AUTH-001", location: "" }));

  const fpR = fingerprintOf(m, limits);
  const fs = sortFindings(dedupe(findings)).slice(0, limits.maxFindings);
  const s = scoreFindings(fs, { partial });
  return {
    grade: s.grade,
    score: s.score,
    partial,
    caps: s.caps,
    deductions: s.deductions,
    findings: fs,
    capabilityProfile,
    scope: "metadata-only",
    ...(sid && isRecord(sid) ? { sessionIdShape: { length: Number(sid.length) || 0, charset: sid.charset, sequentialSuspected: Boolean(sid.sequentialSuspected) } } : {}),
    fingerprint: fpR,
    rulesetVersion: `${ruleset.rulesetId}@${ruleset.version}+${ruleset.sequence}`,
    engineVersion: ENGINE_VERSION,
    degraded: degradedReasons.length > 0,
    degradedReasons: [...new Set(degradedReasons)],
    elapsedMs: Math.max(0, performance.now() - t0),
  };
}
