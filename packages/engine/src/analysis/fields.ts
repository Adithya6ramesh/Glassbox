// C3 (engine-spec §5.3): field enumeration with roles, per surface. Iterative.
import { jcs } from "../util/jcs.js";
import { isRecord, ptrSeg } from "../util/misc.js";

export interface Field {
  pointer: string;
  kind: "string" | "key";
  role: string;
  text: string;
  /** JSON key the string sits under (for key-name-sensitive detectors). */
  keyName: string | undefined;
  /** Index of the tool this field belongs to (manifest only). */
  toolIndex?: number;
}

interface Walk { v: unknown; pointer: string; path: string[]; key: string | undefined }

function walk(root: unknown, base: string, emit: (w: Walk, isKey: boolean) => void, maxNodes = 200_000): void {
  const stack: Walk[] = [{ v: root, pointer: base, path: [], key: undefined }];
  let n = 0;
  while (stack.length > 0 && n++ < maxNodes) {
    const w = stack.pop() as Walk;
    const v = w.v;
    if (typeof v === "string") emit(w, false);
    else if (Array.isArray(v)) {
      for (let i = v.length - 1; i >= 0; i--) stack.push({ v: v[i], pointer: `${w.pointer}/${i}`, path: [...w.path, String(i)], key: w.key });
    } else if (isRecord(v)) {
      const keys = Object.keys(v);
      for (let i = keys.length - 1; i >= 0; i--) {
        const k = keys[i] as string;
        const child = { v: v[k], pointer: `${w.pointer}/${ptrSeg(k)}`, path: [...w.path, k], key: k };
        stack.push(child);
      }
      // Keys are fields too (emitted in document order before values).
      for (const k of keys) emit({ v: k, pointer: `${w.pointer}/${ptrSeg(k)}`, path: [...w.path, k], key: k }, true);
    }
  }
}

function schemaRole(path: string[], isKey: boolean): string {
  // path inside inputSchema/outputSchema
  const last = path[path.length - 1] ?? "";
  const parent = path[path.length - 2] ?? "";
  if (isKey) return parent === "properties" ? "tool.schema.key" : "tool.schema.other";
  if (path.includes("enum")) return "tool.schema.enum";
  if (path.includes("examples")) return "tool.schema.examples";
  if (last === "default" || path.includes("default")) return "tool.schema.default";
  if (last === "const") return "tool.schema.const";
  if (last === "description") return "tool.schema.description";
  if (last === "title") return "tool.schema.title";
  return "tool.schema.other";
}

export function manifestFields(m: unknown, maxTools: number): Field[] {
  const out: Field[] = [];
  walk(m, "", (w, isKey) => {
    // "key~dupN" (a duplicated JSON key, §5.2) takes the role of "key".
    const p = w.path.map((seg) => seg.replace(/~dup\d+$/, ""));
    let role = "manifest.other";
    let toolIndex: number | undefined;
    if (p[0] === "initialize") {
      if (p[1] === "instructions" && !isKey) role = "server.instructions";
      else if (p[1] === "serverInfo") role = "server.info";
    } else if (p[0] === "tools" && p.length >= 2) {
      toolIndex = Number(p[1]);
      if (toolIndex >= maxTools) return;
      const f = p[2];
      if (p.length === 3 && !isKey && (f === "name" || f === "title" || f === "description")) role = `tool.${f}`;
      else if (f === "annotations") role = "tool.annotation";
      else if ((f === "inputSchema" || f === "outputSchema") && p.length > 3) role = schemaRole(p.slice(3), isKey);
      else if (isKey && p.length === 3) role = "tool.key";
      else role = "tool.other";
    } else if (p[0] === "prompts") role = p[2] === "name" && p.length === 3 ? "prompt.name" : "prompt.text";
    else if (p[0] === "resources" || p[0] === "resourceTemplates") role = "resource.text";
    // Ordinary structural keys are not interesting text.
    if (isKey && (role === "manifest.other" || role === "tool.key" || role === "tool.other" || role === "tool.annotation" || role === "server.info" || role === "prompt.text" || role === "resource.text")) return;
    out.push({ pointer: w.pointer, kind: isKey ? "key" : "string", role, text: String(w.v), keyName: w.key, ...(toolIndex !== undefined ? { toolIndex } : {}) });
  });
  // Non-string enum/default/const values are scanned in JCS form (§5.3).
  const tools = isRecord(m) && Array.isArray(m["tools"]) ? (m["tools"] as unknown[]) : [];
  tools.slice(0, maxTools).forEach((t, ti) => {
    for (const s of ["inputSchema", "outputSchema"]) {
      const sch = isRecord(t) ? t[s] : undefined;
      walkNonString(sch, `/tools/${ti}/${s}`, (pointer, value, role) => out.push({ pointer, kind: "string", role, text: value, keyName: undefined, toolIndex: ti }));
    }
  });
  return out;
}

function walkNonString(root: unknown, base: string, emit: (pointer: string, text: string, role: string) => void) {
  const stack: { v: unknown; pointer: string }[] = [{ v: root, pointer: base }];
  let n = 0;
  while (stack.length > 0 && n++ < 50_000) {
    const { v, pointer } = stack.pop() as { v: unknown; pointer: string };
    if (Array.isArray(v)) v.forEach((x, i) => stack.push({ v: x, pointer: `${pointer}/${i}` }));
    else if (isRecord(v)) {
      for (const k of Object.keys(v)) {
        const x = v[k];
        if ((k === "default" || k === "const") && x !== null && typeof x === "object") {
          try { emit(`${pointer}/${ptrSeg(k)}`, jcs(x), k === "default" ? "tool.schema.default" : "tool.schema.const"); } catch { /* skip */ }
        }
        stack.push({ v: x, pointer: `${pointer}/${ptrSeg(k)}` });
      }
    }
  }
}

export function genericFields(root: unknown, base: string, role: string, keyRole: string): Field[] {
  const out: Field[] = [];
  walk(root, base, (w, isKey) => {
    out.push({ pointer: w.pointer, kind: isKey ? "key" : "string", role: isKey ? keyRole : role, text: String(w.v), keyName: w.key });
  });
  return out;
}

export function roleMatches(patterns: readonly string[] | undefined, role: string): boolean {
  if (!patterns || patterns.length === 0) return true;
  for (const p of patterns) {
    if (p === "*" || p === role) return true;
    if (p.endsWith(".*") && role.startsWith(p.slice(0, -1))) return true;
  }
  return false;
}
