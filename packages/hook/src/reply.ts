// What the hook writes back to Claude Code.
//
// JSON on stdout with exit 0 is the main method (verified with Claude Code 2.1.332: a JSON
// deny blocks in every mode tested and Claude sees only our reason). Exit 2 + stderr is used
// only when writing JSON fails: Claude Code then shows Claude the hook's whole command line
// too, so the stderr reason is reduced to plain words (no paths, no secrets).
import * as v from "valibot";
import { redact, type Verdict } from "@glassbox-ai/engine";
import { ConfigChangeOutput, PreToolUseOutput } from "@glassbox-ai/protocol";

export interface Reply {
  exitCode: 0 | 2;
  stdout: string;
  stderr: string;
}

export const EMPTY_REPLY: Reply = Object.freeze({ exitCode: 0, stdout: "", stderr: "" }) as Reply;

export interface OutputFlags {
  /**
   * Fields not yet verified against a real Claude Code (systemMessage, additionalContext,
   * every PostToolUse output). Off by default; only `experimental.unverifiedHookOutputs` in
   * ~/.glassbox/config.json turns it on.
   */
  unverifiedHookOutputs: boolean;
}

const clip = (s: string, max: number) => (s.length <= max ? s : `${s.slice(0, max - 1)}…`);
const nonEmpty = (s: string, fallback: string) => (s.trim().length > 0 ? s : fallback);

/** The PreToolUse reply for a verdict. */
export function preReply(d: { verdict: Verdict; reason: string; alert?: string }, flags: OutputFlags): Reply {
  const out: Record<string, unknown> = {};
  if (flags.unverifiedHookOutputs && d.alert) out["systemMessage"] = clip(d.alert, 1000);

  if (d.verdict === "deny" || d.verdict === "ask") {
    const fallback = d.verdict === "deny" ? "Blocked by Glassbox." : "Glassbox asks you to confirm this action.";
    out["hookSpecificOutput"] = {
      hookEventName: "PreToolUse",
      permissionDecision: d.verdict,
      permissionDecisionReason: clip(nonEmpty(d.reason, fallback), 2000),
    };
  } else if (d.verdict === "warn" && flags.unverifiedHookOutputs && d.reason.trim()) {
    out["systemMessage"] ??= clip(d.reason, 1000);
    out["hookSpecificOutput"] = { hookEventName: "PreToolUse", additionalContext: clip(d.reason, 2000) };
  }

  if (Object.keys(out).length === 0) return EMPTY_REPLY;
  // Our own contract check: a reply that doesn't fit is never sent as JSON.
  if (!v.is(PreToolUseOutput, out)) {
    return d.verdict === "deny" || d.verdict === "ask" ? exit2Fallback(d.reason) : EMPTY_REPLY;
  }
  return { exitCode: 0, stdout: JSON.stringify(out), stderr: "" };
}

/**
 * ConfigChange: block the settings change (verified with 2.1.332: the session keeps its previous
 * settings; nothing is shown). Exit 2 is the fallback, as for PreToolUse.
 */
export function configChangeBlockReply(reason: string): Reply {
  const out = { decision: "block", reason: clip(nonEmpty(reason, "Blocked by Glassbox."), 2000) };
  return v.is(ConfigChangeOutput, out) ? { exitCode: 0, stdout: JSON.stringify(out), stderr: "" } : exit2Fallback(reason);
}

/** Exit 2 blocks the call; stderr becomes the reason Claude sees. */
export function exit2Fallback(reason: string): Reply {
  return { exitCode: 2, stdout: "", stderr: sanitizeStderrReason(reason) };
}

// Plain words only: letters, apostrophes and inner hyphens, with one trailing punctuation
// mark. Anything with a slash, backslash, dot inside, digit, underscore, @, = or quote is
// dropped, which removes paths, file names, URLs, tokens and key=value pairs.
const PLAIN_WORD = /^[A-Za-z][A-Za-z'-]{0,30}[.,:;!?)]?$/;

/** Reduce a reason to plain words for stderr (no paths, no secrets, no control characters). */
export function sanitizeStderrReason(reason: string): string {
  let text = typeof reason === "string" ? reason : "";
  try {
    const r = redact(text);
    if (typeof r.value === "string") text = r.value;
  } catch {
    text = "";
  }
  // Control characters become spaces; \s also covers the Unicode line and paragraph separators.
  const words = text.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").split(/\s+/).filter((w) => PLAIN_WORD.test(w));
  let out = "";
  for (const w of words) {
    if (out.length + w.length + 1 > 300) break;
    out = out ? `${out} ${w}` : w;
  }
  return out || "Blocked by Glassbox.";
}

export interface ReplyIO {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

/**
 * Write the reply and return the exit code. If writing JSON to stdout fails and the reply
 * blocks (`blockingReason` non-empty), fall back to exit 2 so the call is still blocked.
 */
export function writeReply(reply: Reply, io: ReplyIO, blockingReason: string): number {
  if (reply.stdout) {
    try {
      io.stdout(reply.stdout);
    } catch {
      if (!blockingReason) return 0;
      const fb = exit2Fallback(blockingReason);
      try {
        io.stderr(fb.stderr);
      } catch {
        // Nothing more can be done; exit 2 still blocks (with no reason shown).
      }
      return 2;
    }
  }
  if (reply.stderr) {
    try {
      io.stderr(reply.stderr);
    } catch {
      // Exit code 2 still blocks.
    }
  }
  return reply.exitCode;
}

/** The reason inside a blocking JSON reply (deny, ask, or a ConfigChange block), or "" when the reply doesn't block. */
export function blockingReasonOf(reply: Reply): string {
  if (reply.exitCode === 2) return reply.stderr || "Blocked by Glassbox.";
  if (!reply.stdout) return "";
  try {
    const o = JSON.parse(reply.stdout) as { decision?: string; reason?: string; hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
    if (o.decision === "block" && o.hookSpecificOutput === undefined) return o.reason ?? "Blocked by Glassbox.";
    const h = o.hookSpecificOutput;
    return h && (h.permissionDecision === "deny" || h.permissionDecision === "ask") ? (h.permissionDecisionReason ?? "Blocked by Glassbox.") : "";
  } catch {
    return "";
  }
}
