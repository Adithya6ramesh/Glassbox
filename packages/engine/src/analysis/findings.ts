// Finding construction (engine-spec §4.1, §8.3) and the rule-metadata lookup.
import { makeEvidence } from "../evidence/evidence.js";
import type { Category, Finding, LoadedRuleset, RuleDef, Severity, ViaKind } from "../types.js";
import { sha256Hex } from "../util/hash.js";

/** Minimal metadata for engine-emitted rules, used only if a ruleset lacks the rule. */
const FALLBACK: Record<string, [Category, Severity]> = {
  "CP-ACTION-001": ["dangerous-action", "critical"], "CP-FLOW-002": ["toxic-flow", "critical"], "CP-SRVREQ-002": ["server-request", "critical"],
  "CP-SRVREQ-010": ["server-request", "critical"], "CP-SELF-001": ["self-protection", "high"], "CP-SELF-002": ["self-protection", "high"],
  "CP-SELF-003": ["self-protection", "high"], "CP-SHELL-001": ["obfuscation", "medium"],
};

export class FindingFactory {
  private byId = new Map<string, RuleDef>();
  constructor(ruleset: LoadedRuleset, readonly evidenceMode: "snippet" | "none") {
    for (const r of ruleset.rules) this.byId.set(r.id, r);
  }

  rule(id: string): RuleDef | undefined {
    return this.byId.get(id);
  }

  has(id: string): boolean {
    return this.byId.has(id);
  }

  make(args: {
    ruleId: string;
    location: string;
    text?: string;
    start?: number;
    end?: number;
    via?: ViaKind[];
    severity?: Severity;
    confidence?: number;
    related?: string[];
    explanation?: string;
  }): Finding | null {
    const r = this.byId.get(args.ruleId);
    const fb = FALLBACK[args.ruleId];
    if (!r && !fb) return null;
    const via = args.via ?? [];
    const text = args.text ?? "";
    const start = Math.max(0, Math.min(args.start ?? 0, text.length));
    const end = Math.max(start, Math.min(args.end ?? Math.min(text.length, start + 80), text.length));
    const f: Finding = {
      id: sha256Hex(`${args.ruleId}\u0000${args.location}\u0000${via.join(",")}`).slice(0, 16),
      ruleId: args.ruleId,
      ruleSource: args.ruleId.startsWith("PV-") ? "private" : "baseline",
      category: r?.category ?? (fb as [Category, Severity])[0],
      severity: args.severity ?? r?.severity ?? (fb as [Category, Severity])[1],
      confidence: Math.round((args.confidence ?? r?.confidence ?? 1) * 100) / 100,
      location: args.location,
      evidence: text.length > 0 ? makeEvidence(text, start, end, this.evidenceMode) : this.evidenceMode === "none" ? "[evidence withheld by policy]" : '""',
      explanation: args.explanation ?? r?.explanation ?? `Glassbox rule ${args.ruleId} matched.`,
      remediation: r?.remediation ?? "Review this action.",
    };
    if (text.length > 0) f.span = { start: cpOffset(text, start), end: cpOffset(text, end) };
    if (via.length > 0) f.via = via;
    if (args.related && args.related.length > 0) f.related = args.related;
    return f;
  }
}

function cpOffset(s: string, utf16: number): number {
  let n = 0;
  for (let i = 0; i < utf16 && i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < utf16) i++;
    n++;
  }
  return n;
}

const SEV: Severity[] = ["info", "low", "medium", "high", "critical"];
export const sevRank = (s: Severity) => SEV.indexOf(s);

export function sortFindings(fs: Finding[]): Finding[] {
  return fs.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0) || (a.location < b.location ? -1 : a.location > b.location ? 1 : 0));
}

/** One finding per (rule, location): keep the most severe. */
export function dedupe(fs: (Finding | null)[]): Finding[] {
  const m = new Map<string, Finding>();
  for (const f of fs) {
    if (!f) continue;
    const k = f.ruleId + "\u0000" + f.location;
    const prev = m.get(k);
    if (!prev || sevRank(f.severity) > sevRank(prev.severity)) m.set(k, f);
  }
  return [...m.values()];
}
