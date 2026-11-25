// What the Glassbox hook writes to stdout. These schemas describe Glassbox's own output
// contract, which is narrower than what Claude Code accepts:
//
// - PreToolUse: only "deny" or "ask". An allow or warn verdict returns NO permission
//   decision, so Claude Code's own permission prompts still apply and Glassbox never
//   makes a call less gated than plain Claude Code. "allow" and "defer" are rejected.
// - Glassbox never rewrites tool input: `updatedInput` is rejected.
// - Strict objects: Claude Code silently ignores fields at the wrong nesting level, so a
//   misplaced field must fail here instead of silently doing nothing.
//
// Observed with Claude Code 2.1.332 on Windows, `-p` mode, hook run both by Git Bash and
// with `"shell": "powershell"` (fixtures: test/fixtures/claude-code/2.1.332-win32/output/):
//
// - VERIFIED deny (exit 0 + JSON): the call is blocked in "default" and "acceptEdits"
//   mode, also when an explicit allow rule matches the command and when Claude Code
//   would auto-approve it as read-only. Claude receives exactly
//   "PreToolUse:<tool> hook error: <permissionDecisionReason>".
// - VERIFIED deny (exit 2 + stderr): also blocks, in both hook shells (the exit code
//   survives PowerShell). But Claude receives the hook's command line and plugin name:
//   "PreToolUse:<tool> hook error: [<hook command>]: <stderr>\nThis hook comes from the
//   <plugin> plugin." That exposes the install path to the model, so JSON is the primary
//   reply and exit 2 is only the fallback when JSON can't be produced.
// - VERIFIED ask in -p mode: the call is refused (nobody can answer the prompt) and Claude
//   receives exactly the permissionDecisionReason. No PermissionRequest event fires.
//   TODO-VERIFY: that an interactive session shows the reason in its permission prompt.
// - VERIFIED no decision (exit 0, empty stdout): the call follows the normal flow.
// - VERIFIED a refused call gets no PostToolUse, PostToolUseFailure or PermissionDenied
//   event; only its PostToolBatch entry records it, with the text Claude saw.
// - TODO-VERIFY: systemMessage, additionalContext and all PostToolUse output fields
//   (not exercised yet).
import * as v from "valibot";

const Text = (max: number) => v.pipe(v.string(), v.minLength(1), v.maxLength(max));

/** Universal fields, valid on any event. */
const universal = {
  systemMessage: v.optional(Text(1000)), // TODO-VERIFY: shown to the user
  suppressOutput: v.optional(v.boolean()), // TODO-VERIFY
};

export const PreToolUseOutput = v.strictObject({
  ...universal,
  hookSpecificOutput: v.optional(
    v.strictObject({
      hookEventName: v.literal("PreToolUse"), // VERIFIED
      permissionDecision: v.optional(v.picklist(["deny", "ask"])), // VERIFIED (both)
      // VERIFIED: deny → Claude sees it after "PreToolUse:<tool> hook error: ";
      // ask in -p → Claude sees it verbatim. TODO-VERIFY: ask in the interactive prompt.
      permissionDecisionReason: v.optional(Text(2000)),
      additionalContext: v.optional(Text(2000)), // TODO-VERIFY: added to Claude's context
    }),
  ),
});

/** TODO-VERIFY (whole schema): PostToolUse output has not been exercised yet. */
export const PostToolUseOutput = v.pipe(
  v.strictObject({
    ...universal,
    decision: v.optional(v.literal("block")), // advisory only: Claude still sees the original output
    reason: v.optional(Text(2000)),
    hookSpecificOutput: v.optional(
      v.strictObject({
        hookEventName: v.literal("PostToolUse"),
        additionalContext: v.optional(Text(2000)),
        // Replaces what Claude sees. Must match the tool's response shape (tools.ts).
        updatedToolOutput: v.optional(v.unknown()),
      }),
    ),
  }),
  v.check((o) => o.decision === undefined || o.reason !== undefined, "decision \"block\" needs a reason"),
);

export type PreToolUseOutput = v.InferOutput<typeof PreToolUseOutput>;
export type PostToolUseOutput = v.InferOutput<typeof PostToolUseOutput>;
