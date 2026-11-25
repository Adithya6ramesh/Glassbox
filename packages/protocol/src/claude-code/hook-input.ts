// Claude Code hook stdin payloads: what Claude Code writes to a command hook's stdin.
//
// Every field carries a status:
// - VERIFIED: seen in real payloads captured from Claude Code 2.1.332 on Windows
//   (test/fixtures/claude-code/).
// - TODO-VERIFY: from the public Claude Code hooks documentation only, not yet seen in a
//   captured payload. The hook must not base a security decision on a TODO-VERIFY field
//   until a fixture confirms it.
//
// Objects are loose: Claude Code adds fields between releases (2.1.332 sends
// `noOutputExpected`, `background_tasks` and `session_crons`, which the docs don't list).
// Unknown fields are kept and ignored, so a new field never breaks the hook. A missing or
// mistyped required field fails the parse, and the hook then applies its fail rules.
import * as v from "valibot";

/** The Claude Code build the VERIFIED fields were captured from. */
export const VERIFIED_WITH = { claudeCode: "2.1.332", platform: "win32" } as const;

/** Plain JSON object (not null, not an array). */
export function isPlainRecord(x: unknown): x is Record<string, unknown> {
  if (x === null || typeof x !== "object" || Array.isArray(x)) return false;
  const proto: unknown = Object.getPrototypeOf(x);
  return proto === Object.prototype || proto === null;
}

// Tool input and output are passed through by reference, never rebuilt. Rebuilding
// (as valibot's object schemas do) can drop keys such as "__proto__"; the engine would
// then not see data that the tool itself still receives.
const ToolInput = v.custom<Record<string, unknown>>(isPlainRecord, "tool_input must be a JSON object");
const NonEmpty = v.pipe(v.string(), v.minLength(1));

/** Permission modes named in the docs. VERIFIED: "default", "acceptEdits", "auto". TODO-VERIFY: the rest. */
export const PERMISSION_MODES = ["default", "plan", "acceptEdits", "auto", "dontAsk", "bypassPermissions"] as const;
/** SessionStart `source`. VERIFIED: "startup". TODO-VERIFY: the rest. */
export const SESSION_START_SOURCES = ["startup", "resume", "clear", "compact", "fork"] as const;
/** SessionEnd `reason`. VERIFIED: "other". TODO-VERIFY: the rest. */
export const SESSION_END_REASONS = ["clear", "resume", "logout", "prompt_input_exit", "other"] as const;

// VERIFIED as an object `{ level }` in 2.1.332. TODO-VERIFY: whether older builds send a string.
const Effort = v.union([v.looseObject({ level: v.optional(v.string()) }), v.string()]);

const common = {
  session_id: NonEmpty, // VERIFIED (a UUID in 2.1.332; the format is not enforced)
  transcript_path: v.optional(v.string()), // VERIFIED on every event
  cwd: NonEmpty, // VERIFIED
  scratchpad_dir: v.optional(v.string()), // VERIFIED on every event
  prompt_id: v.optional(v.string()), // VERIFIED on every event except SessionStart
  // VERIFIED on tool, prompt and stop events; absent on SessionStart, SubagentStart and
  // SessionEnd. Kept as a string so a new mode doesn't fail the parse: compare against
  // PERMISSION_MODES and treat anything else as unknown.
  permission_mode: v.optional(v.string()),
  effort: v.optional(Effort),
  agent_id: v.optional(v.string()), // VERIFIED inside subagents
  agent_type: v.optional(v.string()), // VERIFIED inside subagents
};

const event = <N extends string, E extends v.ObjectEntries>(name: N, entries: E) =>
  v.looseObject({ ...common, hook_event_name: v.literal(name), ...entries });

export const SessionStartInput = event("SessionStart", {
  source: v.string(), // VERIFIED ("startup"); see SESSION_START_SOURCES
});

export const UserPromptSubmitInput = event("UserPromptSubmit", {
  prompt: v.string(), // VERIFIED
});

export const PreToolUseInput = event("PreToolUse", {
  tool_name: NonEmpty, // VERIFIED
  tool_input: ToolInput, // VERIFIED
  tool_use_id: NonEmpty, // VERIFIED; the key that pairs Pre with Post
});

export const PostToolUseInput = event("PostToolUse", {
  tool_name: NonEmpty, // VERIFIED
  tool_input: ToolInput, // VERIFIED. TODO-VERIFY: original or rewritten input when another hook returned updatedInput
  tool_response: v.unknown(), // VERIFIED; shape depends on the tool (see tools.ts)
  tool_use_id: NonEmpty, // VERIFIED
  duration_ms: v.optional(v.number()), // VERIFIED
});

/** A tool that ran and failed. For Bash a non-zero exit lands here, not in PostToolUse (VERIFIED). */
export const PostToolUseFailureInput = event("PostToolUseFailure", {
  tool_name: NonEmpty, // VERIFIED
  tool_input: ToolInput, // VERIFIED
  tool_use_id: NonEmpty, // VERIFIED
  error: v.string(), // VERIFIED; for Bash: "Exit code <n>\n<stderr>"
  is_interrupt: v.optional(v.boolean()), // VERIFIED
  duration_ms: v.optional(v.number()), // VERIFIED
});

const BatchCall = v.looseObject({
  tool_name: NonEmpty, // VERIFIED
  tool_input: ToolInput, // VERIFIED
  tool_use_id: NonEmpty, // VERIFIED
  // VERIFIED: the tool's response object, or a plain string when the call was refused
  // by Claude Code's permission system (refused calls get no PostToolUse event).
  tool_response: v.optional(v.unknown()),
});
export const PostToolBatchInput = event("PostToolBatch", {
  tool_calls: v.array(BatchCall), // VERIFIED
});

/** Claude Code is about to show its permission prompt (or, in -p mode, refuse). */
export const PermissionRequestInput = event("PermissionRequest", {
  tool_name: NonEmpty, // VERIFIED
  tool_input: ToolInput, // VERIFIED
  permission_suggestions: v.optional(v.array(v.unknown())), // VERIFIED
  // VERIFIED ABSENT in 2.1.332: PermissionRequest can't be paired with its PreToolUse by id.
  tool_use_id: v.optional(v.string()),
});

/**
 * TODO-VERIFY (whole event): in 2.1.332 -p runs it fired neither for permission refusals
 * nor for hook deny/ask. Fields from the docs.
 */
export const PermissionDeniedInput = event("PermissionDenied", {
  tool_name: NonEmpty, // TODO-VERIFY
  tool_input: v.optional(ToolInput), // TODO-VERIFY
  tool_use_id: v.optional(v.string()), // TODO-VERIFY
});

export const SubagentStartInput = event("SubagentStart", {
  agent_id: NonEmpty, // VERIFIED
  agent_type: v.string(), // VERIFIED
});

export const SubagentStopInput = event("SubagentStop", {
  agent_id: NonEmpty, // VERIFIED
  agent_type: v.string(), // VERIFIED
  stop_hook_active: v.boolean(), // VERIFIED
  agent_transcript_path: v.optional(v.string()), // VERIFIED
  last_assistant_message: v.optional(v.string()), // VERIFIED
});

export const StopInput = event("Stop", {
  stop_hook_active: v.boolean(), // VERIFIED
  last_assistant_message: v.optional(v.string()), // VERIFIED
  background_tasks: v.optional(v.array(v.unknown())), // VERIFIED (not in the docs)
  session_crons: v.optional(v.array(v.unknown())), // VERIFIED (not in the docs)
});

export const SessionEndInput = event("SessionEnd", {
  reason: v.string(), // VERIFIED ("other"); see SESSION_END_REASONS
});

/** TODO-VERIFY (whole event): not captured yet. */
export const ConfigChangeInput = event("ConfigChange", {
  source: v.string(), // TODO-VERIFY: user_settings | project_settings | local_settings | policy_settings | skills
  file_path: v.optional(v.string()), // TODO-VERIFY
});

/** TODO-VERIFY (whole event): registered in the capture but did not fire. */
export const NotificationInput = event("Notification", {
  message: v.optional(v.string()), // TODO-VERIFY
});

/** TODO-VERIFY (whole event): not captured yet; only the common fields are assumed. */
export const ElicitationInput = event("Elicitation", {});

/** Any other event: only the common fields are checked. */
const GenericInput = v.looseObject({ ...common, hook_event_name: NonEmpty });

const SCHEMAS = {
  SessionStart: SessionStartInput,
  UserPromptSubmit: UserPromptSubmitInput,
  PreToolUse: PreToolUseInput,
  PostToolUse: PostToolUseInput,
  PostToolUseFailure: PostToolUseFailureInput,
  PostToolBatch: PostToolBatchInput,
  PermissionRequest: PermissionRequestInput,
  PermissionDenied: PermissionDeniedInput,
  SubagentStart: SubagentStartInput,
  SubagentStop: SubagentStopInput,
  Stop: StopInput,
  SessionEnd: SessionEndInput,
  ConfigChange: ConfigChangeInput,
  Notification: NotificationInput,
  Elicitation: ElicitationInput,
} as const;

export type KnownHookEvent = keyof typeof SCHEMAS;
export const KNOWN_HOOK_EVENTS = Object.keys(SCHEMAS) as KnownHookEvent[];
export type HookInput = { [K in KnownHookEvent]: v.InferOutput<(typeof SCHEMAS)[K]> }[KnownHookEvent];
export type GenericHookInput = v.InferOutput<typeof GenericInput>;

export type HookInputIssue = { path: string; message: string };
export type ParseHookInputResult =
  | { ok: true; known: true; input: HookInput }
  | { ok: true; known: false; input: GenericHookInput }
  | { ok: false; reason: "not-an-object" | "missing-event-name" | "event-mismatch" | "invalid"; issues: HookInputIssue[] };

const MAX_ISSUES = 5;

function isKnownEvent(name: string): name is KnownHookEvent {
  return Object.hasOwn(SCHEMAS, name);
}

/**
 * Validate a parsed hook payload. Never throws.
 *
 * `expected` is the event the hook was registered for (the hook knows it from its own
 * command line). A payload whose `hook_event_name` differs is rejected, so a PreToolUse
 * registration can't be talked into treating its input as some other event.
 *
 * Issues name the field path and the problem but never echo input values, so they are
 * safe to log (tool input can hold secrets).
 */
export function parseHookInput(raw: unknown, expected?: KnownHookEvent): ParseHookInputResult {
  if (!isPlainRecord(raw)) return { ok: false, reason: "not-an-object", issues: [] };
  const name = raw["hook_event_name"];
  if (typeof name !== "string" || name.length === 0) return { ok: false, reason: "missing-event-name", issues: [] };
  if (expected !== undefined && name !== expected) {
    return { ok: false, reason: "event-mismatch", issues: [{ path: "hook_event_name", message: `expected ${expected}` }] };
  }
  if (!isKnownEvent(name)) {
    const r = v.safeParse(GenericInput, raw);
    return r.success ? { ok: true, known: false, input: r.output } : invalid(r.issues);
  }
  const r = v.safeParse(SCHEMAS[name], raw);
  return r.success ? { ok: true, known: true, input: r.output as HookInput } : invalid(r.issues);
}

function invalid(issues: readonly v.BaseIssue<unknown>[]): ParseHookInputResult {
  return {
    ok: false,
    reason: "invalid",
    issues: issues.slice(0, MAX_ISSUES).map((i) => ({
      path: (i.path ?? []).map((p) => String(p.key)).join(".") || "(root)",
      message: `expected ${i.expected ?? "a valid value"}`,
    })),
  };
}

/**
 * Exit code of a failed shell command, from PostToolUseFailure `error`.
 * VERIFIED format (Bash, 2.1.332): "Exit code 2\n<stderr>". PostToolUse for a
 * successful command carries no exit code at all. TODO-VERIFY: PowerShell and Monitor.
 * Returns null when the text doesn't start with that exact prefix.
 */
export function exitCodeFromFailure(error: string): number | null {
  const m = /^Exit code (\d{1,3})(?:\n|$)/.exec(error);
  if (m === null) return null;
  const n = Number(m[1]);
  return n <= 255 ? n : null;
}
