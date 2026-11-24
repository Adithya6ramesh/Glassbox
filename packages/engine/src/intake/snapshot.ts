// C2.4: snapshot an object input into frozen null-prototype data.
// Reads only own enumerable data properties via descriptors (getters are never invoked),
// detects cycles, drops non-JSON values, survives hostile Proxies, bounded and iterative.
import { parseJsonStrict, type IntakeIssue } from "./json.js";
import { deepFreeze } from "../util/misc.js";

export interface SnapshotResult { value: unknown; issues: IntakeIssue[]; degraded: boolean }
export interface SnapshotOptions { maxDepth?: number; maxNodes?: number; maxStringBytes?: number; maxBytes?: number }

const ptrSeg = (k: string | number) => String(k).replace(/~/g, "~0").replace(/\//g, "~1");

export function snapshot(input: unknown, opts: SnapshotOptions = {}): SnapshotResult {
  const issues: IntakeIssue[] = [];
  const maxDepth = opts.maxDepth ?? 32;
  const maxNodes = opts.maxNodes ?? 100_000;
  let degraded = false;
  let nodes = 0;
  let bytes = 0;
  const maxBytes = opts.maxBytes ?? Number.POSITIVE_INFINITY;
  const onPath = new Set<object>();

  interface Job { src: unknown; set: (v: unknown) => void; depth: number; pointer: string; exit?: object }
  let root: unknown = null;
  const jobs: Job[] = [{ src: input, set: (v) => { root = v; }, depth: 0, pointer: "" }];

  while (jobs.length > 0) {
    const job = jobs.pop() as Job;
    if (job.exit) { onPath.delete(job.exit); continue; }
    const src = job.src;
    if (++nodes > maxNodes) { issues.push({ code: "CP-LIMIT-003", pointer: job.pointer }); degraded = true; break; }
    try {
      if (typeof src === "string") {
        bytes += src.length;
        if (bytes > maxBytes) { issues.push({ code: "CP-LIMIT-001", pointer: job.pointer }); degraded = true; break; }
        job.set(src);
        continue;
      }
      if (src === null || typeof src === "boolean") { job.set(src); continue; }
      if (typeof src === "number") { job.set(Number.isFinite(src) ? src : null); continue; }
      if (typeof src !== "object") { issues.push({ code: "CP-PARSE-009", pointer: job.pointer }); continue; }
      if (src instanceof Uint8Array) {
        const r = parseJsonStrict(src, opts);
        issues.push(...r.issues);
        job.set(r.ok ? r.value : null);
        if (!r.ok) degraded = true;
        continue;
      }
      if (onPath.has(src)) { issues.push({ code: "CP-PARSE-007", pointer: job.pointer }); job.set(null); continue; }
      if (job.depth >= maxDepth) { issues.push({ code: "CP-LIMIT-002", pointer: job.pointer }); degraded = true; job.set(null); continue; }
      onPath.add(src);
      jobs.push({ src: null, set: () => undefined, depth: 0, pointer: "", exit: src });
      const isArray = Array.isArray(src);
      const out: unknown = isArray ? [] : Object.create(null);
      job.set(out);
      const keys = Object.keys(src);
      if (isArray) {
        const len = (Object.getOwnPropertyDescriptor(src, "length")?.value as number | undefined) ?? 0;
        for (let i = 0; i < Math.min(len, maxNodes); i++) {
          const d = Object.getOwnPropertyDescriptor(src, String(i));
          if (!d) { (out as unknown[]).push(null); continue; }
          if (!("value" in d)) { issues.push({ code: "CP-PARSE-006", pointer: `${job.pointer}/${i}` }); (out as unknown[]).push(null); continue; }
          const idx = (out as unknown[]).length;
          (out as unknown[]).push(null);
          jobs.push({ src: d.value, set: (v) => { (out as unknown[])[idx] = v; }, depth: job.depth + 1, pointer: `${job.pointer}/${i}` });
        }
        continue;
      }
      // Push in reverse so keys are processed (and assigned) in order.
      const pending: Job[] = [];
      for (const k of keys) {
        const d = Object.getOwnPropertyDescriptor(src, k);
        if (!d || !d.enumerable) continue;
        const pointer = `${job.pointer}/${ptrSeg(k)}`;
        if (!("value" in d)) { issues.push({ code: "CP-PARSE-006", pointer }); continue; }
        const v: unknown = d.value;
        if (v === undefined || typeof v === "function" || typeof v === "symbol" || typeof v === "bigint") {
          issues.push({ code: "CP-PARSE-009", pointer });
          continue;
        }
        if (k === "__proto__" || k === "constructor" || k === "prototype") issues.push({ code: "CP-PARSE-003", pointer });
        Object.defineProperty(out, k, { value: null, enumerable: true, writable: true, configurable: true });
        pending.push({ src: v, set: (x) => { (out as Record<string, unknown>)[k] = x; }, depth: job.depth + 1, pointer });
      }
      for (let i = pending.length - 1; i >= 0; i--) jobs.push(pending[i] as Job);
    } catch {
      // A Proxy trap or exotic object threw. Record and continue with what we have.
      degraded = true;
      issues.push({ code: "CP-PARSE-006", pointer: job.pointer });
      job.set(null);
    }
  }
  return { value: deepFreeze(root), issues, degraded };
}
