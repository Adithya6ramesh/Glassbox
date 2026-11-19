// EMBEDDED_BASELINE (engine-spec §10.2, R17). At load the engine hashes the embedded JSON
// text once (SHA-256, ~50 KB) and compares it with the hash recorded at build time. Full
// schema validation and every rule's self-test run in CI (I6), not at every hook start.
import type { ActionTag, LoadedRuleset, RuleDef } from "../types.js";
import { sha256Hex } from "../util/hash.js";
import { deepFreeze } from "../util/misc.js";
import { BASELINE_JSON, BASELINE_SHA256 } from "./baseline.generated.js";

const FALLBACK_IRREVERSIBLE: readonly ActionTag[] = [
  "fs.destroy", "vcs.force-push", "vcs.history-rewrite", "vcs.discard-changes", "db.unscoped-write", "db.ddl",
  "deploy.prod", "infra.change", "payment", "publish.public", "message.send", "perm.change", "config.agent", "exec.nested-agent",
];

interface Payload {
  rulesetId: string; version: string; sequence: number; expiresAt: string;
  irreversibleTags?: ActionTag[]; rules: RuleDef[];
}

function build(): LoadedRuleset {
  try {
    if (sha256Hex(BASELINE_JSON) !== BASELINE_SHA256) throw new Error("integrity");
    const p = JSON.parse(BASELINE_JSON) as Payload;
    if (!Array.isArray(p.rules) || typeof p.sequence !== "number") throw new Error("shape");
    return deepFreeze({
      status: "ok",
      rulesetId: p.rulesetId,
      version: p.version,
      sequence: p.sequence,
      expiresAt: p.expiresAt,
      expired: false,
      protectionDegraded: false,
      rules: p.rules,
      irreversibleTags: p.irreversibleTags ?? FALLBACK_IRREVERSIBLE,
      errors: [],
    });
  } catch {
    return deepFreeze({
      status: "unavailable",
      rulesetId: "glassbox-baseline",
      version: "unavailable",
      sequence: 0,
      expiresAt: "1970-01-01T00:00:00Z",
      expired: false,
      protectionDegraded: false,
      rules: [],
      irreversibleTags: FALLBACK_IRREVERSIBLE,
      errors: ["embedded baseline failed its integrity check"],
    });
  }
}

export const EMBEDDED_BASELINE: LoadedRuleset = build();
