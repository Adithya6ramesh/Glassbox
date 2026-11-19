// Ruleset payload schema (engine-spec §10.1–10.2), validated with valibot.
import * as v from "valibot";
import { ACTION_TAGS, type Matcher } from "../types.js";

const CATEGORIES = [
  "tool-poisoning", "hidden-content", "prompt-injection", "shadowing", "rug-pull", "exfiltration", "secret-exposure",
  "dangerous-action", "obfuscation", "capability-mismatch", "self-protection", "integrity", "resource-limit", "hygiene",
  "server-request", "toxic-flow",
] as const;
const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const SURFACES = ["manifest", "call", "result", "server-request"] as const;
const VIEWS = ["norm", "skeleton", "visible", "original", "tagDecoded", "decoded"] as const;

const MatcherSchema: v.GenericSchema<Matcher> = v.lazy(() =>
  v.variant("type", [
    v.object({ type: v.literal("phrase"), phrases: v.pipe(v.array(v.pipe(v.string(), v.minLength(1), v.maxLength(200))), v.minLength(1), v.maxLength(500)), wordBoundary: v.boolean(), maxGapWords: v.optional(v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(5))) }),
    v.object({ type: v.literal("regex"), pattern: v.pipe(v.string(), v.minLength(1), v.maxLength(2000)), flags: v.optional(v.literal("i")), anchors: v.optional(v.pipe(v.array(v.pipe(v.string(), v.minLength(1), v.maxLength(64))), v.minLength(1), v.maxLength(64))) }),
    v.object({ type: v.literal("codepoints"), ranges: v.array(v.tuple([v.number(), v.number()])), minCount: v.number(), exclude: v.optional(v.literal("emoji-sequences")) }),
    v.object({ type: v.literal("secret"), detector: v.string() }),
    v.object({ type: v.literal("structural"), check: v.string() }),
    v.object({ type: v.picklist(["all", "any"]), of: v.pipe(v.array(MatcherSchema), v.minLength(1), v.maxLength(10)), scope: v.literal("field") }),
    v.object({ type: v.literal("not"), of: MatcherSchema }),
  ]) as unknown as v.GenericSchema<Matcher>,
);

const TestCase = v.object({ surface: v.picklist(SURFACES), input: v.unknown(), note: v.optional(v.string()) });

export const RuleSchema = v.object({
  id: v.pipe(v.string(), v.regex(/^(CP|PV)-[A-Z]+-\d{3}$/)),
  revision: v.pipe(v.number(), v.integer(), v.minValue(1)),
  category: v.picklist(CATEGORIES),
  severity: v.picklist(SEVERITIES),
  confidence: v.pipe(v.number(), v.minValue(0), v.maxValue(1)),
  surfaces: v.pipe(v.array(v.picklist(SURFACES)), v.minLength(1)),
  target: v.object({ roles: v.optional(v.array(v.string())), keys: v.optional(v.boolean()) }),
  views: v.pipe(v.array(v.picklist(VIEWS)), v.minLength(1)),
  matcher: MatcherSchema,
  escalation: v.optional(v.boolean()),
  suppressible: v.boolean(),
  explanation: v.pipe(v.string(), v.minLength(1), v.maxLength(500)),
  remediation: v.pipe(v.string(), v.minLength(1), v.maxLength(500)),
  testCases: v.object({ positive: v.array(TestCase), negative: v.array(TestCase) }),
});

export const PayloadSchema = v.object({
  rulesetId: v.pipe(v.string(), v.minLength(1), v.maxLength(100)),
  channel: v.picklist(["baseline", "private"]),
  version: v.pipe(v.string(), v.maxLength(50)),
  sequence: v.pipe(v.number(), v.integer(), v.minValue(0)),
  createdAt: v.string(),
  expiresAt: v.string(),
  minEngineVersion: v.pipe(v.string(), v.regex(/^\d+\.\d+\.\d+$/)),
  irreversibleTags: v.optional(v.array(v.picklist(ACTION_TAGS))),
  rules: v.pipe(v.array(RuleSchema), v.maxLength(5000)),
});

export type RulesetPayload = v.InferOutput<typeof PayloadSchema>;

export const EnvelopeSchema = v.object({
  format: v.literal("glassbox-ruleset-envelope/v1"),
  payload: v.pipe(v.string(), v.maxLength(6 * 1024 * 1024)),
  signatures: v.pipe(v.array(v.object({ keyId: v.string(), alg: v.literal("ed25519"), sig: v.string() })), v.minLength(1), v.maxLength(8)),
});
