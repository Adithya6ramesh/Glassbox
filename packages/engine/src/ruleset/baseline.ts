// EMBEDDED_BASELINE (engine-spec §10.2, R17). Validated and integrity-checked once at
// module load. The full per-rule self-test runs in CI (I6), not at every hook start.
import * as v from "valibot";
import type { ActionTag, LoadedRuleset, RuleDef } from "../types.js";
import { sha256Hex } from "../util/hash.js";
import { jcs } from "../util/jcs.js";
import { deepFreeze } from "../util/misc.js";
import { BASELINE_PAYLOAD, BASELINE_SHA256 } from "./baseline.generated.js";
import { PayloadSchema } from "./schema.js";

const FALLBACK_IRREVERSIBLE: readonly ActionTag[] = [
  "fs.destroy", "vcs.force-push", "vcs.history-rewrite", "vcs.discard-changes", "db.unscoped-write", "db.ddl",
  "deploy.prod", "infra.change", "payment", "publish.public", "message.send", "perm.change", "config.agent", "exec.nested-agent",
];

function build(): LoadedRuleset {
  try {
    if (sha256Hex(jcs(BASELINE_PAYLOAD)) !== BASELINE_SHA256) throw new Error("integrity");
    const parsed = v.safeParse(PayloadSchema, BASELINE_PAYLOAD);
    if (!parsed.success) throw new Error("schema");
    const p = parsed.output;
    return deepFreeze({
      status: "ok",
      rulesetId: p.rulesetId,
      version: p.version,
      sequence: p.sequence,
      expiresAt: p.expiresAt,
      expired: false,
      protectionDegraded: false,
      rules: p.rules as unknown as readonly RuleDef[],
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
