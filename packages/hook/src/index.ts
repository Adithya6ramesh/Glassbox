// @glassbox-ai/hook: library surface (the process entry point is main.ts).
export { parseArgs } from "./args.js";
export { buildContext, loadConfig, projectOf, resolvedPathsFor, type Config, type HookEnv } from "./context.js";
export { eventLine, HOOK_VERSION, inputDigest, ulid } from "./events.js";
export { failReply, failVerdict, type FailCause } from "./failrules.js";
export { blockingReasonOf, EMPTY_REPLY, exit2Fallback, preReply, sanitizeStderrReason, writeReply, type OutputFlags, type Reply } from "./reply.js";
export { batchOutcome, closeOutcome, EVENT_ARGS, isEventArg, reasonFor, runHook, type HookEventArg } from "./run.js";
export { safeId, Store, type PendingDecision } from "./store.js";
export { summarize, summarizeCommand, summarizePath } from "./summary.js";
