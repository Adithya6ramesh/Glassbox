// Fingerprints (engine-spec §9.1–9.2): SHA-256 over RFC 8785 canonical JSON of the snapshot.
import type { Fingerprint, ItemFingerprint, Limits, ToolFingerprint } from "../types.js";
import { sha256Hex } from "../util/hash.js";
import { jcs } from "../util/jcs.js";
import { get, getString, isRecord } from "../util/misc.js";
import { DEFAULT_LIMITS } from "../limits.js";
import { redactString, redactValue } from "../secrets/redact.js";

const H = (v: unknown): string => sha256Hex(jcs(v === undefined ? null : v));
/** Snapshots are output, so they are redacted (hashes are computed over the raw values). */
const cap = (v: unknown): unknown => {
  try {
    return jcs(v ?? null).length > 16 * 1024 ? "[truncated]" : redactValue(v ?? null, DEFAULT_LIMITS).value;
  } catch {
    return null;
  }
};
const capText = (s: string): string => redactString(s.slice(0, 16 * 1024), "description", DEFAULT_LIMITS).text;

function items(list: unknown, key: "name" | "uri" | "uriTemplate"): ItemFingerprint[] {
  if (!Array.isArray(list)) return [];
  const out = list.map((x, i) => ({ name: getString(x, key) ?? getString(x, "name") ?? `#${i}`, hash: H(x) }));
  return dedupNames(out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.hash < b.hash ? -1 : 1)));
}

function dedupNames<T extends { name: string }>(xs: T[]): T[] {
  const seen = new Map<string, number>();
  return xs.map((x) => {
    const n = seen.get(x.name) ?? 0;
    seen.set(x.name, n + 1);
    return n === 0 ? x : { ...x, name: `${x.name}~${n}` };
  });
}

export function fingerprintOf(m: unknown, limits: Limits): Fingerprint {
  const init = get(m, "initialize");
  const instructions = get(init, "instructions");
  const serverInfo = get(init, "serverInfo");
  const toolsRaw = Array.isArray(get(m, "tools")) ? (get(m, "tools") as unknown[]) : [];
  const truncated = toolsRaw.length > limits.maxTools;
  const tools: ToolFingerprint[] = dedupNames(
    toolsRaw.slice(0, limits.maxTools).map((t, i) => {
      const name = getString(t, "name") ?? `#${i}`;
      const part = (k: string) => H(get(t, k) ?? null);
      return {
        name,
        hash: H({ name, title: get(t, "title") ?? null, description: get(t, "description") ?? null, inputSchema: get(t, "inputSchema") ?? null, outputSchema: get(t, "outputSchema") ?? null, annotations: get(t, "annotations") ?? null }),
        parts: { title: part("title"), description: part("description"), inputSchema: part("inputSchema"), outputSchema: part("outputSchema"), annotations: part("annotations") },
        snapshot: { description: typeof get(t, "description") === "string" ? capText(get(t, "description") as string) : "", inputSchema: cap(get(t, "inputSchema")), annotations: cap(get(t, "annotations")), title: capText(getString(t, "title") ?? "") },
      };
    }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.hash < b.hash ? -1 : 1)),
  );
  const prompts = items(get(m, "prompts"), "name");
  const resources = items(get(m, "resources"), "uri");
  const resourceTemplates = items(get(m, "resourceTemplates"), "uriTemplate");
  const server = {
    instructions: instructions === undefined ? null : H(instructions),
    serverInfo: serverInfo === undefined ? null : H(serverInfo),
  };
  const manifest = H({
    instructions: instructions ?? null,
    serverInfo: serverInfo ?? null,
    tools: tools.map((t) => t.hash),
    prompts: prompts.map((p) => p.hash),
    resources: resources.map((r) => r.hash),
    resourceTemplates: resourceTemplates.map((r) => r.hash),
  });
  return {
    algorithm: "glassbox-fp-v1",
    manifest,
    server,
    serverSnapshot: { name: getString(serverInfo, "name") ?? null, title: getString(serverInfo, "title") ?? null, version: getString(serverInfo, "version") ?? null },
    tools,
    prompts,
    resources,
    resourceTemplates,
    truncated,
  };
}

export function isFingerprint(v: unknown): v is Fingerprint {
  return isRecord(v) && typeof v["manifest"] === "string" && Array.isArray(v["tools"]) && isRecord(v["server"]);
}
