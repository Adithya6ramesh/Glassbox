// Built-in Claude Code tools, by what they can do. Taken from the Claude Code tools reference
// (https://code.claude.com/docs/en/tools-reference), checked 2026-11-25 (Claude Code 2.1.331).
// A built-in tool that isn't listed here is unanalyzable: ask, or deny in autopilot.
// test/static/builtin-tools.test.ts keeps this table in step with a hand-updated list.
import type { BuiltinToolCategory } from "../types.js";

export const BUILTIN_TOOLS: Readonly<Record<string, BuiltinToolCategory>> = Object.freeze({
  // Runs commands: full shell analysis.
  Bash: "command",
  PowerShell: "command",
  Monitor: "command",

  // Writes files.
  Edit: "write",
  Write: "write",
  NotebookEdit: "write",
  EnterWorktree: "write",
  ExitWorktree: "write",

  // Network: sends data off the machine.
  WebFetch: "network",
  WebSearch: "network",
  Artifact: "network",
  ShareOnboardingGuide: "network",

  // Spawns agents or schedules agent work. Their tool calls are checked on their own.
  Agent: "agent",
  Workflow: "agent",
  Skill: "agent",
  SendMessage: "agent",
  CronCreate: "agent",
  ScheduleWakeup: "agent",
  RemoteTrigger: "agent",

  // Reads only.
  Read: "read",
  Glob: "read",
  Grep: "read",
  LSP: "read",
  ListMcpResourcesTool: "read",
  ReadMcpResourceTool: "read",
  ToolSearch: "read",
  TaskGet: "read",
  TaskList: "read",
  CronList: "read",
  ListAgents: "read",
  ListPlugins: "read",
  ListSkills: "read",
  SearchPlugins: "read",
  SearchSkills: "read",
  WaitForMcpServers: "read",

  // Other: conversation, planning, task list and notification tools that act only inside the session.
  AskUserQuestion: "other",
  EndConversation: "other",
  EnterPlanMode: "other",
  ExitPlanMode: "other",
  propose_skills: "other",
  PushNotification: "other",
  ReportFindings: "other",
  SendFeedback: "other",
  SendUserFile: "other",
  SubagentHandback: "other",
  SuggestPluginInstall: "other",
  SuggestSkills: "other",
  TaskCreate: "other",
  TaskStop: "other",
  TaskUpdate: "other",
  TodoWrite: "other",
  CronDelete: "other",

  // Older names still accepted from earlier Claude Code versions.
  Task: "agent",
  MultiEdit: "write",
  LS: "read",
  NotebookRead: "read",
  TodoRead: "other",
  BashOutput: "read",
  TaskOutput: "read",
});

const LOWER: ReadonlyMap<string, BuiltinToolCategory> = new Map(Object.entries(BUILTIN_TOOLS).map(([k, v]) => [k.toLowerCase(), v]));

/** Category of a built-in tool, matched case-insensitively; undefined if unknown. */
export function builtinCategory(name: string): BuiltinToolCategory | undefined {
  return LOWER.get(name.toLowerCase());
}
