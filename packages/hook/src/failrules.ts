// What to answer when the hook can't check a call (bad input, timeout, internal error).
// Read-only built-ins fail open; every other tool, and any tool we can't name, fails closed.
import { configChangeBlockReply, EMPTY_REPLY, preReply, type Reply } from "./reply.js";

/** Exact names only. A look-alike ("read", "Read ", "mcp__x__Read") is not read-only. */
const READ_ONLY_TOOLS: ReadonlySet<string> = new Set(["Read", "Glob", "Grep", "WebSearch", "TodoWrite"]);

/** Read-only built-in tools run even in strict mode (exact names only). */
export function isReadOnlyTool(toolName: unknown): boolean {
  return typeof toolName === "string" && READ_ONLY_TOOLS.has(toolName);
}

export function failVerdict(toolName: unknown): "allow" | "deny" {
  return typeof toolName === "string" && READ_ONLY_TOOLS.has(toolName) ? "allow" : "deny";
}

export type FailCause = "invalid input" | "timeout" | "internal error";

/**
 * The reply for a failure. PreToolUse fails by the rule above; a settings change Glassbox couldn't
 * check is blocked (fail closed); every other event just exits 0.
 */
export function failReply(event: string | null, toolName: unknown, cause: FailCause): Reply {
  if (event === "config-change") return configChangeBlockReply(`Blocked by Glassbox: it couldn't check this settings change (${cause}).`);
  if (event !== "pre" || failVerdict(toolName) === "allow") return EMPTY_REPLY;
  return preReply({ verdict: "deny", reason: `Blocked by Glassbox: it couldn't check this action (${cause}).` }, { unverifiedHookOutputs: false });
}
