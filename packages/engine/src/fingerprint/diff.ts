// Fingerprint diff (engine-spec §9.3) and the cloaking check (§9.4).
import { FindingFactory } from "../analysis/findings.js";
import { displayTokens } from "../evidence/evidence.js";
import { EMBEDDED_BASELINE } from "../ruleset/baseline.js";
import type { ChangeKind, DiffOptions, Finding, ManifestChange, ManifestDiff, ToolFingerprint } from "../types.js";
import { isRecord, ptrSeg } from "../util/misc.js";
import { jcs } from "../util/jcs.js";
import { isFingerprint } from "./fingerprint.js";

const RULE: Record<ChangeKind, string> = {
  "tool-added": "CP-RUGPULL-001", "tool-removed": "CP-RUGPULL-002", "description-changed": "CP-RUGPULL-003", "title-changed": "CP-RUGPULL-004",
  "schema-widened": "CP-RUGPULL-005", "schema-narrowed": "CP-RUGPULL-006", "schema-changed-indeterminate": "CP-RUGPULL-007", "annotations-escalated": "CP-RUGPULL-008",
  "annotations-changed": "CP-RUGPULL-009", "server-instructions-changed": "CP-RUGPULL-010", "serverinfo-changed": "CP-RUGPULL-011", "prompt-added": "CP-RUGPULL-012",
  "resource-added": "CP-RUGPULL-012", "output-schema-changed": "CP-RUGPULL-013", "fingerprint-incomparable": "CP-RUGPULL-014",
};

const esc = (s: string) => displayTokens(s.slice(0, 120)).join("");

type Effect = { widen: boolean; narrow: boolean; indeterminate: boolean };
const IGNORED = new Set(["description", "title", "examples", "$comment", "deprecated"]);
const same = (a: unknown, b: unknown) => { try { return jcs(a ?? null) === jcs(b ?? null); } catch { return false; } };

function compareSchema(a: unknown, b: unknown, eff: Effect, depth = 0): void {
  if (depth > 32) { eff.indeterminate = true; return; }
  if (same(a, b)) return;
  if (!isRecord(a) || !isRecord(b)) { if (a === undefined || a === null) eff.narrow = true; else if (b === undefined || b === null) eff.widen = true; else eff.indeterminate = true; return; }
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) {
    if (IGNORED.has(k)) continue;
    const x = a[k], y = b[k];
    if (same(x, y)) continue;
    switch (k) {
      case "properties": {
        const px = isRecord(x) ? x : {}, py = isRecord(y) ? y : {};
        for (const p of new Set([...Object.keys(px), ...Object.keys(py)])) {
          if (!(p in px)) eff.widen = true;
          else if (!(p in py)) eff.narrow = true;
          else compareSchema(px[p], py[p], eff, depth + 1);
        }
        break;
      }
      case "required": {
        const sx = new Set(Array.isArray(x) ? x : []), sy = new Set(Array.isArray(y) ? y : []);
        if ([...sx].some((v) => !sy.has(v))) eff.widen = true;
        if ([...sy].some((v) => !sx.has(v))) eff.narrow = true;
        break;
      }
      case "additionalProperties":
        if (x === false && y !== false) eff.widen = true;
        else if (y === false && x !== false) eff.narrow = true;
        else if (isRecord(x) && isRecord(y)) compareSchema(x, y, eff, depth + 1);
        else if (x === undefined || x === true) eff.narrow = true;
        else eff.indeterminate = true;
        break;
      case "enum": case "const": {
        if (y === undefined) { eff.widen = true; break; }
        if (x === undefined) { eff.narrow = true; break; }
        const ex = new Set((Array.isArray(x) ? x : [x]).map((v) => jcs(v))), ey = new Set((Array.isArray(y) ? y : [y]).map((v) => jcs(v)));
        if ([...ey].some((v) => !ex.has(v))) eff.widen = true;
        if ([...ex].some((v) => !ey.has(v))) eff.narrow = true;
        break;
      }
      case "type": {
        const tx = new Set(Array.isArray(x) ? x : x === undefined ? [] : [x]), ty = new Set(Array.isArray(y) ? y : y === undefined ? [] : [y]);
        if (ty.size === 0) eff.widen = true;
        else if (tx.size === 0) eff.narrow = true;
        else {
          if ([...ty].some((v) => !tx.has(v))) eff.widen = true;
          if ([...tx].some((v) => !ty.has(v))) eff.narrow = true;
        }
        break;
      }
      case "minLength": case "minimum": case "minItems": case "exclusiveMinimum": case "minProperties":
        if (y === undefined || (typeof x === "number" && typeof y === "number" && y < x)) eff.widen = true; else eff.narrow = true;
        break;
      case "maxLength": case "maximum": case "maxItems": case "exclusiveMaximum": case "maxProperties":
        if (y === undefined || (typeof x === "number" && typeof y === "number" && y > x)) eff.widen = true; else eff.narrow = true;
        break;
      case "pattern": case "format":
        if (y === undefined) eff.widen = true; else if (x === undefined) eff.narrow = true; else eff.indeterminate = true;
        break;
      case "items":
        compareSchema(x, y, eff, depth + 1);
        break;
      case "anyOf": case "oneOf": {
        const lx = Array.isArray(x) ? x.length : 0, ly = Array.isArray(y) ? y.length : 0;
        if (ly > lx) eff.widen = true; else if (ly < lx) eff.narrow = true; else eff.indeterminate = true;
        break;
      }
      case "allOf": {
        const lx = Array.isArray(x) ? x.length : 0, ly = Array.isArray(y) ? y.length : 0;
        if (ly < lx) eff.widen = true; else if (ly > lx) eff.narrow = true; else eff.indeterminate = true;
        break;
      }
      default:
        eff.indeterminate = true;
    }
  }
}

/** All "description" strings inside a schema, keyed by pointer. */
function descriptions(s: unknown, base = ""): Map<string, string> {
  const out = new Map<string, string>();
  const stack: { v: unknown; p: string; d: number }[] = [{ v: s, p: base, d: 0 }];
  while (stack.length > 0) {
    const { v, p, d } = stack.pop() as { v: unknown; p: string; d: number };
    if (d > 32) continue;
    if (Array.isArray(v)) v.forEach((x, i) => stack.push({ v: x, p: `${p}/${i}`, d: d + 1 }));
    else if (isRecord(v)) for (const k of Object.keys(v)) {
      if (k === "description" && typeof v[k] === "string") out.set(p, v[k] as string);
      stack.push({ v: v[k], p: `${p}/${ptrSeg(k)}`, d: d + 1 });
    }
  }
  return out;
}

function annotationsEscalated(a: unknown, b: unknown): boolean {
  const g = (o: unknown, k: string) => (isRecord(o) ? o[k] : undefined);
  return (g(a, "readOnlyHint") === true && g(b, "readOnlyHint") !== true) ||
    (g(a, "destructiveHint") !== true && g(b, "destructiveHint") === true) ||
    (g(a, "openWorldHint") === false && g(b, "openWorldHint") === true);
}

function toolChanges(p: ToolFingerprint, n: ToolFingerprint, out: ManifestChange[]): void {
  const item = n.name;
  const ptr = `/tools/${ptrSeg(item)}`;
  if (p.parts.description !== n.parts.description) out.push({ kind: "description-changed", item, pointer: `${ptr}/description`, detail: `description of tool "${esc(item)}" changed` });
  if (p.parts.title !== n.parts.title) out.push({ kind: "title-changed", item, pointer: `${ptr}/title`, detail: `title of tool "${esc(item)}" changed` });
  if (p.parts.inputSchema !== n.parts.inputSchema) {
    const dp = descriptions(p.snapshot.inputSchema), dn = descriptions(n.snapshot.inputSchema);
    for (const [k, v] of dn) if (dp.has(k) && dp.get(k) !== v) out.push({ kind: "description-changed", item, pointer: `${ptr}/inputSchema${k}/description`, detail: `a parameter description of "${esc(item)}" changed` });
    const eff: Effect = { widen: false, narrow: false, indeterminate: false };
    compareSchema(p.snapshot.inputSchema, n.snapshot.inputSchema, eff);
    if (eff.widen) out.push({ kind: "schema-widened", item, pointer: `${ptr}/inputSchema`, detail: `input schema of "${esc(item)}" now accepts more` });
    else if (eff.indeterminate) out.push({ kind: "schema-changed-indeterminate", item, pointer: `${ptr}/inputSchema`, detail: `input schema of "${esc(item)}" changed in a way that can't be classified` });
    else if (eff.narrow) out.push({ kind: "schema-narrowed", item, pointer: `${ptr}/inputSchema`, detail: `input schema of "${esc(item)}" now accepts less` });
  }
  if (p.parts.outputSchema !== n.parts.outputSchema) out.push({ kind: "output-schema-changed", item, pointer: `${ptr}/outputSchema`, detail: `output schema of "${esc(item)}" changed` });
  if (p.parts.annotations !== n.parts.annotations) {
    out.push(annotationsEscalated(p.snapshot.annotations, n.snapshot.annotations)
      ? { kind: "annotations-escalated", item, pointer: `${ptr}/annotations`, detail: `annotations of "${esc(item)}" now describe it as more dangerous` }
      : { kind: "annotations-changed", item, pointer: `${ptr}/annotations`, detail: `annotations of "${esc(item)}" changed` });
  }
}

export function diffImpl(prev: unknown, next: unknown, opts: DiffOptions | undefined): ManifestDiff {
  const ff = new FindingFactory(EMBEDDED_BASELINE, "snippet");
  const changes: ManifestChange[] = [];
  const mk = (c: ManifestChange) => ff.make({ ruleId: RULE[c.kind], location: c.pointer });
  if (!isFingerprint(prev) || !isFingerprint(next) || prev.algorithm !== "glassbox-fp-v1" || next.algorithm !== "glassbox-fp-v1" || prev.truncated || next.truncated) {
    const c: ManifestChange = { kind: "fingerprint-incomparable", item: "", pointer: "", detail: "the fingerprints can't be compared" };
    const f = mk(c);
    return { changed: true, changes: [c], findings: f ? [f] : [], degraded: true };
  }
  if (prev.manifest === next.manifest) return { changed: false, changes: [], findings: [], degraded: false };
  const pt = new Map(prev.tools.map((t) => [t.name, t]));
  const nt = new Map(next.tools.map((t) => [t.name, t]));
  for (const [name, t] of nt) {
    const p = pt.get(name);
    if (!p) { changes.push({ kind: "tool-added", item: name, pointer: `/tools/${ptrSeg(name)}`, detail: `tool "${esc(name)}" added` }); continue; }
    if (p.hash !== t.hash) toolChanges(p, t, changes);
  }
  for (const name of pt.keys()) if (!nt.has(name)) changes.push({ kind: "tool-removed", item: name, pointer: `/tools/${ptrSeg(name)}`, detail: `tool "${esc(name)}" removed` });
  if (prev.server.instructions !== next.server.instructions) changes.push({ kind: "server-instructions-changed", item: "", pointer: "/initialize/instructions", detail: "server instructions changed" });
  if (prev.server.serverInfo !== next.server.serverInfo) {
    const ps = prev.serverSnapshot ?? { name: null, title: null }, ns = next.serverSnapshot ?? { name: null, title: null };
    if (ps.name !== ns.name || ps.title !== ns.title) changes.push({ kind: "serverinfo-changed", item: "", pointer: "/initialize/serverInfo", detail: "server name or title changed" });
  }
  const pp = new Set(prev.prompts.map((x) => x.name)), pr = new Set(prev.resources.map((x) => x.name));
  for (const x of next.prompts) if (!pp.has(x.name)) changes.push({ kind: "prompt-added", item: x.name, pointer: `/prompts/${ptrSeg(x.name)}`, detail: `prompt "${esc(x.name)}" added` });
  for (const x of next.resources) if (!pr.has(x.name)) changes.push({ kind: "resource-added", item: x.name, pointer: `/resources/${ptrSeg(x.name)}`, detail: `resource "${esc(x.name)}" added` });
  const findings: Finding[] = [];
  for (const c of changes) { const f = mk(c); if (f) findings.push(f); }
  if (opts?.baseline === "public-grade") { const f = ff.make({ ruleId: "CP-CLOAK-001", location: "" }); if (f) findings.push(f); }
  return { changed: true, changes, findings, degraded: false };
}
