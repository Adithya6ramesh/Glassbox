// Policy decision table (engine-spec §6.2, rows R1–R17).
import type { ActionRisk, ActionTag, ApprovalMode, Finding, LoadedRuleset, RememberedRule, Severity, UserPolicy, Verdict } from "../types.js";

const ORDER: Verdict[] = ["allow", "warn", "ask", "deny"];
export const vmax = (a: Verdict, b: Verdict): Verdict => (ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b);
const SEV: Severity[] = ["info", "low", "medium", "high", "critical"];

export interface DecideInput {
  kind: "call" | "result" | "server-request";
  risk: ActionRisk;
  findings: readonly Finding[];
  degraded: boolean;
  protectionDegraded: boolean;
  ruleset: LoadedRuleset;
  policy: UserPolicy;
  minConfidence: number;
  serverId: string;
  toolName: string;
  remembered: readonly RememberedRule[];
  /** checkServerRequest: verdict from the kind's policy (R13) and whether it's locked (R14). */
  requestVerdict?: { verdict: Verdict; locked: boolean };
}

export interface DecideOutput { verdict: Verdict; verdictBeforeMode?: Verdict }

/**
 * R3 by mode (spec §6.2, rev 5). Irreversible-or-public tags ask in every mode, so in
 * autopilot they become deny through R15 unless a tag override or a remembered rule lifts
 * the ask first. Other high-risk tags: strict asks, balanced and autopilot warn.
 */
function modeVerdict(tag: ActionTag | null, mode: ApprovalMode, irreversible: ReadonlySet<ActionTag>): Verdict {
  if (tag !== null && irreversible.has(tag)) return "ask";
  return mode === "strict" ? "ask" : "warn";
}

export function decide(d: DecideInput): DecideOutput {
  const mode = d.policy.mode;
  let v: Verdict = "allow";
  const irreversible = new Set(d.ruleset.irreversibleTags);

  // R3 (calls only): high-risk action, by mode, then tagOverrides, then remembered rules.
  if (d.kind === "call" && d.risk.level === "high-risk") {
    const tags = d.risk.tags.filter((t) => t !== "self-protection");
    let r3: Verdict = "allow";
    const askTags: ActionTag[] = [];
    const list: (ActionTag | null)[] = tags.length > 0 ? tags : [null];
    for (const t of list) {
      let tv = modeVerdict(t, mode, irreversible);
      const o = t !== null ? d.policy.tagOverrides?.[t] : undefined;
      if (o === "allow" || o === "ask" || o === "deny") tv = o;
      if (tv === "ask" && t !== null) askTags.push(t);
      r3 = vmax(r3, tv);
    }
    if (r3 === "ask" && askTags.length > 0 && askTags.every((t) => d.remembered.some((m) => m.serverId === d.serverId && m.toolName === d.toolName && m.actionTag === t))) r3 = "allow";
    v = vmax(v, r3);
  }

  // R4–R7: findings (confidence ≥ threshold).
  let top = -1;
  for (const f of d.findings) if (f.confidence >= d.minConfidence) top = Math.max(top, SEV.indexOf(f.severity));
  if (top === 2) v = vmax(v, mode === "strict" ? "ask" : "warn");
  if (top === 3) v = vmax(v, "ask");
  if (top === 4) v = vmax(v, "deny"); // R7 🔒

  // R13/R14: server requests.
  if (d.requestVerdict) v = vmax(v, d.requestVerdict.verdict);

  if (d.kind === "call") {
    if (d.risk.selfProtection) v = vmax(v, "deny"); // R8 🔒
    if (d.risk.unanalyzable) v = vmax(v, "ask"); // R9 🔒
    if (d.degraded && d.risk.level === "high-risk") v = vmax(v, "deny"); // R10 🔒
    if (d.degraded && d.risk.level !== "high-risk") v = vmax(v, "warn"); // R11 🔒
    if (d.protectionDegraded && d.risk.level === "high-risk") v = vmax(v, "ask"); // R16 🔒
  } else if (d.degraded) {
    v = vmax(v, "warn"); // R11 (results and requests: R10 → R11)
  }

  // R17 🔒: no usable rules at all.
  if (d.ruleset.status === "unavailable") v = vmax(v, d.risk.level === "read" ? "warn" : "deny");

  // R15 🔒: nobody is there to answer in autopilot.
  if (mode === "autopilot" && v === "ask") return { verdict: "deny", verdictBeforeMode: "ask" };
  return { verdict: v };
}
