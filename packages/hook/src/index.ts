// @glassbox-ai/hook: library surface (the process entry point is main.ts).
export { parseArgs } from "./args.js";
export { glassboxHomeOf } from "./paths.js";
export { buildContext, loadConfig, projectOf, resolvedPathsFor, type Config, type HookEnv } from "./context.js";
export { eventLine, HOOK_VERSION, inputDigest, SLOW_CHECK_MS, ulid } from "./events.js";
export { failReply, failVerdict, isReadOnlyTool, type FailCause } from "./failrules.js";
export { blockingReasonOf, configChangeBlockReply, EMPTY_REPLY, exit2Fallback, preReply, sanitizeStderrReason, writeReply, type OutputFlags, type Reply } from "./reply.js";
export { batchOutcome, closeOutcome, EVENT_ARGS, HARD_STOP_MS, isEventArg, reasonFor, recordFailure, runHook, writeCallLog, type HookEventArg } from "./run.js";
export { LOG_MAX_BYTES, safeId, SESSION_RETENTION_DAYS, SPOOL_MAX_FILES, Store, type PendingDecision } from "./store.js";
export { summarize, summarizeCommand, summarizePath } from "./summary.js";
export { classifySettingsChange, MAX_SETTINGS_BYTES, parseSettingsBytes, type SettingsClassification, type SettingsLevel, type SettingsReason } from "./settings-classify.js";
export { BURST_MAX, BURST_WINDOW_MS, checkSettings, confirmSettings, onConfigChange, readSettingsFile, SETTINGS_UNVERIFIED_REASON, settingsFiles, type CheckResult, type FileReader, type SettingsFile, type SettingsRecord, type SettingsScope } from "./settings-guard.js";
