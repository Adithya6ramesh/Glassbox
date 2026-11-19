// Layer 1 per field: declarative rules plus the built-in hidden-content checks.
import type { Finding, Limits, Surface } from "../types.js";
import { tokenize } from "./match.js";
import { matchRule, scanField, type FieldScan } from "./match.js";
import type { Field } from "./fields.js";
import { roleMatches } from "./fields.js";
import { FindingFactory } from "./findings.js";

const RE_LATIN = /^\p{Script=Latin}$/u;
const RE_OTHER = /^[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Armenian}\p{Script=Cherokee}\p{Script=Coptic}]$/u;

export interface ScanOutcome {
  findings: Finding[];
  windowed: boolean;
  decodeExhausted: boolean;
  scans: Map<Field, FieldScan>;
  timedOut: boolean;
}

export function mixedScript(text: string): { start: number; end: number } | null {
  for (const t of tokenize(text)) {
    let latin = false, other = false;
    for (const ch of t.w) {
      if (RE_LATIN.test(ch)) latin = true;
      else if (RE_OTHER.test(ch)) other = true;
    }
    if (latin && other) return { start: t.start, end: t.end };
  }
  return null;
}

export function scanFields(fields: Field[], surface: Surface, ff: FindingFactory, rules: readonly import("../types.js").RuleDef[], limits: Limits, hidden: boolean, deadline = Number.POSITIVE_INFINITY): ScanOutcome {
  const findings: (Finding | null)[] = [];
  const scans = new Map<Field, FieldScan>();
  const budget = { bytes: limits.maxDecodedBytes };
  let windowed = false;
  let decodeExhausted = false;
  const declarative = rules.filter((r) => r.matcher.type !== "structural" && r.surfaces.includes(surface));
  let timedOut = false;
  for (const f of fields) {
    if (performance.now() > deadline) { timedOut = true; break; }
    if (f.text.length === 0) continue;
    const scan = scanField(f.text, limits.maxFieldScanBytes, budget, limits.maxDecodeDepth);
    scans.set(f, scan);
    if (scan.windowed) { windowed = true; findings.push(ff.make({ ruleId: "CP-LIMIT-006", location: f.pointer })); }
    if (scan.decodeExhausted) decodeExhausted = true;
    for (const r of declarative) {
      if (!roleMatches(r.target.roles, f.role)) continue;
      if (r.target.keys === false && f.kind === "key") continue;
      const m = matchRule(r, scan, f.kind === "key" ? undefined : f.keyName);
      if (m) findings.push(ff.make({ ruleId: r.id, location: f.pointer, text: f.text, start: m.start, end: m.end, via: m.via, severity: m.severity }));
    }
    if (!hidden) continue;
    const seg = scan.segments[0];
    if (!seg) continue;
    const facts = seg.views.facts;
    const at = (i: number) => ({ text: f.text, start: i, end: i + 1 });
    if (facts.invisibles.length > 0) findings.push(ff.make({ ruleId: "CP-HIDDEN-001", location: f.pointer, ...at(facts.invisibles[0]?.index ?? 0) }));
    if (facts.tagCount > 0 && seg.tagSpan) findings.push(ff.make({ ruleId: "CP-HIDDEN-003", location: f.pointer, text: f.text, start: seg.tagSpan.start, end: seg.tagSpan.end }));
    if (surface === "result") {
      if (facts.ansi > 0) findings.push(ff.make({ ruleId: "CP-HIDDEN-009", location: f.pointer, text: f.text }));
      continue;
    }
    if (facts.bidi.length > 0) findings.push(ff.make({ ruleId: "CP-HIDDEN-002", location: f.pointer, ...at(facts.bidi[0]?.index ?? 0) }));
    if (surface !== "manifest") continue;
    if (facts.ansi > 0) findings.push(ff.make({ ruleId: "CP-HIDDEN-005", location: f.pointer, text: f.text }));
    if (facts.comments) findings.push(ff.make({ ruleId: "CP-HIDDEN-006", location: f.pointer, text: f.text, start: Math.max(0, f.text.indexOf("<!")), end: Math.max(0, f.text.indexOf("<!")) + 4 }));
    if (facts.padding) findings.push(ff.make({ ruleId: "CP-HIDDEN-008", location: f.pointer, text: f.text }));
    const ms = mixedScript(seg.views.visible.text);
    if (ms) {
      const o = seg.views.visible.toOriginal(ms.start);
      findings.push(ff.make({ ruleId: "CP-HIDDEN-004", location: f.pointer, text: f.text, start: o, end: seg.views.visible.toOriginal(ms.end - 1) + 1, ...(f.role === "tool.name" ? { severity: "high" as const } : {}) }));
    }
    const blob = seg.decoded.find((d) => !d.nested);
    if (blob) findings.push(ff.make({ ruleId: blob.end - blob.start >= 256 ? "CP-HIDDEN-010" : "CP-HIDDEN-007", location: f.pointer, text: f.text, start: blob.start, end: blob.end }));
  }
  return { findings: findings.filter((x): x is Finding => x !== null), windowed, decodeExhausted, scans, timedOut };
}
