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
// TODO-VERIFY (whole file): field names and placement are from the public hooks docs.
// The 2.1.332 capture recorded inputs only; no hook output has been exercised yet.
import * as v from "valibot";

const Text = (max: number) => v.pipe(v.string(), v.minLength(1), v.maxLength(max));

/** Universal fields, valid on any event. */
const universal = {
  systemMessage: v.optional(Text(1000)), // shown to the user
  suppressOutput: v.optional(v.boolean()),
};

export const PreToolUseOutput = v.strictObject({
  ...universal,
  hookSpecificOutput: v.optional(
    v.strictObject({
      hookEventName: v.literal("PreToolUse"),
      permissionDecision: v.optional(v.picklist(["deny", "ask"])),
      // deny: shown to Claude; ask: shown to the user in the permission prompt.
      permissionDecisionReason: v.optional(Text(2000)),
      additionalContext: v.optional(Text(2000)), // added to Claude's context
    }),
  ),
});

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
