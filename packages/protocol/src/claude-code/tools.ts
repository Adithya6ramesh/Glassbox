// Per-tool input and response shapes for built-in Claude Code tools.
//
// Why: PostToolUse can replace what Claude sees (`updatedToolOutput`), but for built-in
// tools Claude Code ignores a replacement that doesn't match the tool's output shape.
// The hook may only use `updatedToolOutput` for a tool listed in TOOL_RESPONSE_SHAPES,
// and only after the real response matched that shape; otherwise it falls back to
// advisory feedback and records that honestly.
//
// Only VERIFIED shapes (captured from Claude Code 2.1.332, see hook-input.ts) are listed.
// Tools not listed here (WebFetch, WebSearch, NotebookEdit, MCP tools, ...) are
// TODO-VERIFY: no captured response yet.
import * as v from "valibot";

const shellResponse = {
  stdout: v.string(),
  stderr: v.string(),
  interrupted: v.boolean(),
  isImage: v.optional(v.boolean()),
};

export const BashResponse = v.looseObject({ ...shellResponse, noOutputExpected: v.optional(v.boolean()) });
export const PowerShellResponse = v.looseObject(shellResponse);

/** Monitor starts a background command; its response only describes the task. */
export const MonitorResponse = v.looseObject({
  taskId: v.string(),
  timeoutMs: v.optional(v.number()),
  persistent: v.optional(v.boolean()),
});

export const ReadResponse = v.looseObject({
  type: v.string(),
  file: v.looseObject({
    filePath: v.string(),
    content: v.string(),
    numLines: v.optional(v.number()),
    startLine: v.optional(v.number()),
    totalLines: v.optional(v.number()),
  }),
});

export const WriteResponse = v.looseObject({
  type: v.string(),
  filePath: v.string(),
  content: v.string(),
  structuredPatch: v.optional(v.unknown()),
  originalFile: v.optional(v.nullable(v.string())),
  userModified: v.optional(v.boolean()),
});

export const EditResponse = v.looseObject({
  filePath: v.string(),
  oldString: v.string(),
  newString: v.string(),
  originalFile: v.optional(v.nullable(v.string())),
  structuredPatch: v.optional(v.unknown()),
  userModified: v.optional(v.boolean()),
  replaceAll: v.optional(v.boolean()),
});

export const GlobResponse = v.looseObject({
  filenames: v.array(v.string()),
  numFiles: v.number(),
  truncated: v.optional(v.boolean()),
  durationMs: v.optional(v.number()),
});

export const GrepResponse = v.looseObject({
  mode: v.string(),
  filenames: v.array(v.string()),
  numFiles: v.number(),
});

export const TOOL_RESPONSE_SHAPES = {
  Bash: BashResponse,
  PowerShell: PowerShellResponse,
  Monitor: MonitorResponse,
  Read: ReadResponse,
  Write: WriteResponse,
  Edit: EditResponse,
  Glob: GlobResponse,
  Grep: GrepResponse,
} as const;

export type ShapedTool = keyof typeof TOOL_RESPONSE_SHAPES;

/** True when `response` matches the VERIFIED shape for `toolName`. Unknown tools → false. */
export function matchesKnownResponseShape(toolName: string, response: unknown): boolean {
  if (!Object.hasOwn(TOOL_RESPONSE_SHAPES, toolName)) return false;
  return v.is(TOOL_RESPONSE_SHAPES[toolName as ShapedTool], response);
}

/**
 * Tools that run a shell command from `tool_input.command`.
 * VERIFIED for Bash, PowerShell and Monitor (Monitor: `{ command, description, timeout_ms }`).
 */
export const COMMAND_TOOLS = ["Bash", "PowerShell", "Monitor"] as const;
