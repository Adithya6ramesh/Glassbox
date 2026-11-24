// Grading.
import type { Category, Finding, Grade, Severity } from "../types.js";

const POINTS: Record<Severity, number> = { info: 0, low: 3, medium: 8, high: 20, critical: 40 };
const WEIGHT: Partial<Record<Category, number>> = {
  "tool-poisoning": 1, "hidden-content": 1, shadowing: 1, exfiltration: 1, "secret-exposure": 1, integrity: 0.8, "resource-limit": 1,
  "capability-mismatch": 0.7, hygiene: 0.5, "prompt-injection": 1, "dangerous-action": 0, "rug-pull": 0, "server-request": 0, "toxic-flow": 0,
  obfuscation: 0, "self-protection": 0,
};
const CATEGORY_CAP: Partial<Record<Category, number>> = { "resource-limit": 30, "capability-mismatch": 30, hygiene: 10 };
const SEV: Severity[] = ["info", "low", "medium", "high", "critical"];
const NEVER_A: ReadonlySet<Category> = new Set<Category>(["tool-poisoning", "shadowing"]);
/** Name collisions and spoofed names: CP-SHADOW-010 (also shadowing) and CP-HIDDEN-004 (mixed-script names). */
const NEVER_A_RULES: ReadonlySet<string> = new Set(["CP-SHADOW-010", "CP-HIDDEN-004"]);
/**
 * CP-SPOOF-001 ("official", "endorsed by") is filed under tool-poisoning but is a claim, not a
 * spoofed name or an instruction, and fires on benign text such as "Official SDK client.".
 */
const NEVER_A_EXCEPT: ReadonlySet<string> = new Set(["CP-SPOOF-001"]);
const GRADES: Grade[] = ["A", "B", "C", "D", "F"];
const worse = (a: Grade, b: Grade): Grade => (GRADES.indexOf(a) >= GRADES.indexOf(b) ? a : b);

export interface Score {
  score: number;
  grade: Grade;
  caps: { cap: Grade; reason: string; findingIds: string[] }[];
  deductions: { findingId: string; points: number }[];
}

export function letter(score: number): Grade {
  return score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
}

export function scoreFindings(findings: readonly Finding[], opts: { partial: boolean }): Score {
  const scored = findings
    .filter((f) => f.confidence >= 0.3 && (WEIGHT[f.category] ?? 1) > 0 && POINTS[f.severity] > 0)
    .slice()
    .sort((a, b) => SEV.indexOf(b.severity) - SEV.indexOf(a.severity) || b.confidence - a.confidence || (a.location < b.location ? -1 : a.location > b.location ? 1 : 0));
  // Per rule: repetition factors and a total cap of 2× the first deduction.
  const byRule = new Map<string, { f: Finding; pts: number }[]>();
  for (const f of scored) {
    const list = byRule.get(f.ruleId) ?? [];
    const k = list.length;
    const factor = k === 0 ? 1 : k === 1 ? 0.5 : 0.25;
    list.push({ f, pts: POINTS[f.severity] * f.confidence * (WEIGHT[f.category] ?? 1) * factor });
    byRule.set(f.ruleId, list);
  }
  const perFinding = new Map<string, number>();
  const byCategory = new Map<Category, { id: string; pts: number }[]>();
  for (const list of byRule.values()) {
    const first = list[0]?.pts ?? 0;
    const total = list.reduce((a, x) => a + x.pts, 0);
    const scale = total > 2 * first && total > 0 ? (2 * first) / total : 1;
    for (const x of list) {
      const pts = x.pts * scale;
      const cat = byCategory.get(x.f.category) ?? [];
      cat.push({ id: x.f.id, pts });
      byCategory.set(x.f.category, cat);
    }
  }
  for (const [cat, list] of byCategory) {
    const total = list.reduce((a, x) => a + x.pts, 0);
    const cap = CATEGORY_CAP[cat];
    const scale = cap !== undefined && total > cap ? cap / total : 1;
    for (const x of list) perFinding.set(x.id, (perFinding.get(x.id) ?? 0) + x.pts * scale);
  }
  const sum = [...perFinding.values()].reduce((a, b) => a + b, 0);
  const score = Math.max(0, Math.round(100 - sum + 1e-9));
  let grade = letter(score);
  const caps: Score["caps"] = [];
  const confident = findings.filter((f) => f.confidence >= 0.3 && (WEIGHT[f.category] ?? 1) > 0);
  // The worst finding caps the grade (grading rev 7): critical → F, high → D, medium → C.
  const crit = confident.filter((f) => f.severity === "critical");
  if (crit.length) caps.push({ cap: "F", reason: "Capped at F: a critical finding was found in the metadata.", findingIds: crit.map((f) => f.id) });
  const hidden = confident.filter((f) => f.category === "hidden-content" && SEV.indexOf(f.severity) >= 2);
  if (hidden.length) caps.push({ cap: "D", reason: "Capped at D: hidden content of medium severity or higher was found in the metadata.", findingIds: hidden.map((f) => f.id) });
  const high = confident.filter((f) => f.severity === "high");
  if (high.length) caps.push({ cap: "D", reason: "Capped at D: a high-severity finding was found in the metadata.", findingIds: high.map((f) => f.id) });
  const medium = confident.filter((f) => f.severity === "medium");
  if (medium.length) caps.push({ cap: "C", reason: "Capped at C: a medium-severity finding was found in the metadata.", findingIds: medium.map((f) => f.id) });
  // Poisoning, shadowing, name collisions and spoofed names never get an A, whatever their severity.
  const never = confident.filter((f) => (NEVER_A.has(f.category) && !NEVER_A_EXCEPT.has(f.ruleId)) || NEVER_A_RULES.has(f.ruleId));
  if (never.length) caps.push({ cap: "B", reason: "Capped at B: the metadata shows tool poisoning, shadowing, a name collision or a spoofed name.", findingIds: never.map((f) => f.id) });
  if (opts.partial) caps.push({ cap: "B", reason: "Capped at B: the scan hit a limit, so part of the metadata wasn't analyzed.", findingIds: [] });
  for (const c of caps) grade = worse(grade, c.cap);
  return {
    score,
    grade,
    caps,
    deductions: [...perFinding].map(([findingId, points]) => ({ findingId, points: Math.round(points * 1000) / 1000 })),
  };
}
