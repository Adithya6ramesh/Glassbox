// Public types (engine-spec §4). Kept free of logic.

export type Verdict = "allow" | "warn" | "ask" | "deny";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ActionRiskLevel = "read" | "write-reversible" | "high-risk";
export type ApprovalMode = "autopilot" | "balanced" | "strict";
export type Grade = "A" | "B" | "C" | "D" | "F";

export type Category =
  | "tool-poisoning" | "hidden-content" | "prompt-injection" | "shadowing" | "rug-pull"
  | "exfiltration" | "secret-exposure" | "dangerous-action" | "obfuscation" | "capability-mismatch"
  | "self-protection" | "integrity" | "resource-limit" | "hygiene" | "server-request" | "toxic-flow";

export const ACTION_TAGS = [
  "fs.read", "fs.read.sensitive", "fs.write", "fs.delete", "fs.destroy", "fs.move", "net.egress",
  "net.fetch.package-manager", "net.fetch.vcs", "vcs.commit", "vcs.push", "vcs.force-push",
  "vcs.history-rewrite", "vcs.discard-changes", "db.read", "db.write", "db.delete", "db.ddl",
  "db.unscoped-write", "deploy.prod", "deploy.other", "infra.change", "payment", "publish.public",
  "message.send", "perm.change", "exec.inline-code", "exec.project-code", "exec.unknown",
  "exec.nested-agent", "config.agent", "self-protection",
] as const;
export type ActionTag = (typeof ACTION_TAGS)[number];

export type ViaKind = "base64" | "hex" | "url" | "tag-chars" | "concat" | "skeleton" | "invisible-stripped";

export interface Finding {
  id: string;
  ruleId: string;
  ruleSource: "baseline" | "private";
  category: Category;
  severity: Severity;
  confidence: number;
  location: string;
  span?: { start: number; end: number };
  via?: readonly ViaKind[];
  related?: readonly string[];
  evidence: string;
  explanation: string;
  remediation: string;
}

export interface ActionRisk {
  level: ActionRiskLevel;
  tags: readonly ActionTag[];
  unanalyzable: boolean;
  selfProtection: boolean;
  reasons: readonly string[];
}

export type SessionSignal =
  | { kind: "sensitive-read"; label: string; atCall: number }
  | { kind: "injection-seen"; serverId: string; mentionedTools: readonly string[]; atCall: number }
  | { kind: "secret-seen"; secretType: string; atCall: number }
  | { kind: "private-data-read"; source: string; serverId: string; toolName: string; atCall: number }
  | { kind: "untrusted-content-seen"; serverId: string; toolName: string; atCall: number }
  | { kind: "external-write"; serverId: string; toolName: string; tags: readonly ActionTag[]; atCall: number }
  | { kind: "protection-degraded"; reason: "tampered" | "downgrade" | "internal-error"; atCall: number };

export interface Decision {
  verdict: Verdict;
  actionRisk: ActionRisk;
  findings: readonly Finding[];
  rulesetVersion: string;
  engineVersion: string;
  degraded: boolean;
  degradedReasons: readonly string[];
  protectionDegraded: boolean;
  signals: readonly SessionSignal[];
  suppressed: readonly { ruleId: string; count: number }[];
  mode: ApprovalMode;
  verdictBeforeMode?: Verdict;
  inputDigest: string;
  resultRewrite?: { kind: "redact-secrets" | "replace-with-notice"; value: unknown };
  elapsedMs: number;
}

export interface ToolDef {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: { title?: string; readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean; [k: string]: unknown };
  [k: string]: unknown;
}

export interface ServerManifest {
  serverId?: string;
  initialize?: {
    protocolVersion?: string;
    serverInfo?: { name?: string; version?: string; title?: string; [k: string]: unknown };
    capabilities?: Record<string, unknown>;
    instructions?: string;
    [k: string]: unknown;
  };
  tools?: readonly ToolDef[];
  prompts?: readonly Record<string, unknown>[];
  resources?: readonly Record<string, unknown>[];
  resourceTemplates?: readonly Record<string, unknown>[];
  [k: string]: unknown;
}

export interface Limits {
  maxInputBytes: number;
  maxDepth: number;
  maxNodes: number;
  maxTools: number;
  maxDescriptionBytes: number;
  maxFieldScanBytes: number;
  maxCommandBytes: number;
  maxSqlBytes: number;
  maxDecodeDepth: number;
  maxDecodedBytes: number;
  maxFindings: number;
  maxStringBytes: number;
  timeBudgetMs: number;
  hardStopMs: number;
  signalTtlCalls: number;
  minConfidenceForVerdict: number;
}

export interface AnalyzeOptions {
  knownTools?: readonly { serverId: string; name: string }[];
  limits?: Partial<Limits>;
  ruleset?: LoadedRuleset;
  evidenceMode?: "snippet" | "none";
  sessionIdShape?: ServerReport["sessionIdShape"];
}

export interface ServerReport {
  grade: Grade;
  score: number;
  partial: boolean;
  caps: readonly { cap: Grade; reason: string; findingIds: readonly string[] }[];
  deductions: readonly { findingId: string; points: number }[];
  findings: readonly Finding[];
  capabilityProfile: readonly { tool: string; risk: ActionRisk }[];
  scope: "metadata-only";
  sessionIdShape?: { length: number; charset: "hex" | "base64" | "alnum" | "digits" | "other"; sequentialSuspected: boolean };
  fingerprint: Fingerprint;
  rulesetVersion: string;
  engineVersion: string;
  degraded: boolean;
  degradedReasons: readonly string[];
  elapsedMs: number;
}

export interface ToolCallInput {
  serverId: string;
  toolName: string;
  arguments: unknown;
  descriptor?: ToolDef;
  agent?: string;
}

export interface ToolResultInput {
  call: ToolCallInput;
  result: unknown;
  isError?: boolean;
}

export type ServerRequestKind = "sampling" | "elicitation" | "roots" | "ping" | "notification" | "unknown";

export interface ServerRequestInput {
  serverId: string;
  message: unknown;
}

export interface RememberedRule {
  projectIdHash: string;
  serverId: string;
  toolName: string;
  actionTag: ActionTag;
  createdAt: string;
}

export type PolicyChoice = "allow" | "ask" | "deny";

export interface UserPolicy {
  mode: ApprovalMode;
  tagOverrides?: Partial<Record<ActionTag, PolicyChoice>>;
  disabledRules?: readonly string[];
  extraProtectedPaths?: readonly string[];
  extraSensitivePaths?: readonly string[];
  serverRequests?: {
    default?: Partial<Record<ServerRequestKind, PolicyChoice>>;
    perServer?: Readonly<Record<string, Partial<Record<ServerRequestKind, PolicyChoice>>>>;
  };
}

export interface SessionContext {
  sessionId: string;
  platform: "linux" | "darwin" | "win32";
  claudeConfigDir?: string;
  glassboxSecretPaths?: readonly string[];
  remembered?: readonly RememberedRule[];
  homeDir: string;
  cwd: string;
  caseInsensitiveFs: boolean;
  glassboxDirs: readonly string[];
  resolvedPaths?: Readonly<Record<string, string>>;
  servers: readonly {
    serverId: string;
    toolNames: readonly string[];
    highRiskTools?: readonly string[];
    identity?: { host?: string; issuerTags?: readonly string[] };
  }[];
  signals?: readonly SessionSignal[];
  policy: UserPolicy;
  ruleset: LoadedRuleset;
  limits?: Partial<Limits>;
  evidenceMode?: "snippet" | "none";
}

export interface ActionContext {
  platform?: SessionContext["platform"];
  homeDir?: string;
  cwd?: string;
  caseInsensitiveFs?: boolean;
  glassboxDirs?: readonly string[];
}

// ── Fingerprints ─────────────────────────────────────────────────────────

export interface ItemFingerprint { name: string; hash: string }
export interface ToolFingerprint {
  name: string;
  hash: string;
  parts: { title: string; description: string; inputSchema: string; outputSchema: string; annotations: string };
  snapshot: { description: string; inputSchema: unknown; annotations: unknown; title: string };
}
export interface Fingerprint {
  algorithm: "glassbox-fp-v1";
  manifest: string;
  server: { instructions: string | null; serverInfo: string | null };
  serverSnapshot: { name: string | null; title: string | null; version: string | null };
  tools: readonly ToolFingerprint[];
  prompts: readonly ItemFingerprint[];
  resources: readonly ItemFingerprint[];
  resourceTemplates: readonly ItemFingerprint[];
  truncated: boolean;
}
export type FingerprintResult =
  | { ok: true; fingerprint: Fingerprint; findings: readonly Finding[] }
  | { ok: false; findings: readonly Finding[]; degraded: true };

export type ChangeKind =
  | "tool-added" | "tool-removed" | "description-changed" | "title-changed" | "schema-widened"
  | "schema-narrowed" | "schema-changed-indeterminate" | "annotations-escalated" | "annotations-changed"
  | "server-instructions-changed" | "serverinfo-changed" | "prompt-added" | "resource-added"
  | "output-schema-changed" | "fingerprint-incomparable";

export interface ManifestChange { kind: ChangeKind; item: string; pointer: string; detail: string }
export interface ManifestDiff { changed: boolean; changes: readonly ManifestChange[]; findings: readonly Finding[]; degraded: boolean }
export interface DiffOptions { baseline?: "approved" | "public-grade" }

// ── Redaction ────────────────────────────────────────────────────────────

export interface RedactOptions { evidenceMode?: "snippet" | "none"; limits?: Partial<Limits> }
export interface Redacted {
  value: unknown;
  redactions: readonly { pointer: string; type: string; masked: string }[];
  truncated: boolean;
}

// ── Rulesets ─────────────────────────────────────────────────────────────

export type ViewName = "norm" | "skeleton" | "visible" | "original" | "tagDecoded" | "decoded";
export type Surface = "manifest" | "call" | "result" | "server-request";

export type Matcher =
  | { type: "phrase"; phrases: readonly string[]; wordBoundary: boolean; maxGapWords?: number }
  /**
   * `anchors` (spec rev 6): literals of which every match contains at least one, compared
   * against the lowercased text. When none occurs, the regex pass is skipped. Anchors are
   * lowercase; non-ASCII anchors are only allowed without the `i` flag (re2's case folding and
   * toLowerCase differ outside ASCII). Baseline anchors are proven by test/ruleset/anchors.test.
   */
  | { type: "regex"; pattern: string; flags?: "i"; anchors?: readonly string[] }
  | { type: "codepoints"; ranges: readonly (readonly [number, number])[]; minCount: number; exclude?: "emoji-sequences" }
  | { type: "secret"; detector: string }
  | { type: "structural"; check: string }
  | { type: "all" | "any"; of: readonly Matcher[]; scope: "field" }
  | { type: "not"; of: Matcher };

export interface RuleTestCase { surface: Surface; input: unknown; note?: string }

export interface RuleDef {
  id: string;
  revision: number;
  category: Category;
  severity: Severity;
  confidence: number;
  surfaces: readonly Surface[];
  target: { roles?: readonly string[]; keys?: boolean };
  views: readonly ViewName[];
  matcher: Matcher;
  escalation?: boolean;
  suppressible: boolean;
  explanation: string;
  remediation: string;
  testCases: { positive: readonly RuleTestCase[]; negative: readonly RuleTestCase[] };
}

export interface LoadedRuleset {
  status: "ok" | "loaded-with-errors" | "fallback" | "unavailable";
  rulesetId: string;
  version: string;
  sequence: number;
  expiresAt: string;
  /** "now" passed to loadRuleset; used only to compute `expired`. */
  expired: boolean;
  protectionDegraded: boolean;
  degradedCause?: "tampered" | "downgrade";
  rules: readonly RuleDef[];
  irreversibleTags: readonly ActionTag[];
  errors: readonly string[];
}

export interface TrustedKey { keyId: string; publicKey: Uint8Array }

export interface LoadRulesetOptions {
  minSequence: number;
  now: string;
  /** Test/dev only. Production callers must not pass this; the embedded keys apply. */
  trustedKeys?: readonly TrustedKey[];
}
