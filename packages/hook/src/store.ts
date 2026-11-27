// Local state under ~/.glassbox (the engine denies the agent any write there).
//
//   config.json                    mode + experimental flags (written by the CLI)
//   remembered.json                "allow & remember" rules (written by the CLI)
//   device-salt                    random salt for project id hashes
//   sessions/<sid>/signals.jsonl   engine session signals, append-only
//   sessions/<sid>/pending/<id>    one open decision per tool call, closed by a later event
//   spool/<ts>-<pid>-<rand>.jsonl  events for the uploader, written whole then renamed
//   spool/dropped.json             how many events were dropped because the spool was full
//   logs/hook.log (+ hook.log.1)   one line per hook call: ids, verdicts, rule ids, timings; no content
//
// Parallel tool calls run parallel hook processes, so nothing here is a shared read-modify-
// write file: one file per decision, one spool file per process, single-call appends. (The
// dropped counter is the exception; a lost increment there is acceptable.)
//
// Nothing is trusted just because it is in ~/.glassbox: a file read here must be a regular file
// (not a link) owned by this user. On Linux and macOS, group- or world-writable state is fixed
// to owner-only (warn and fix, never refuse to run).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { SessionSignal } from "@glassbox-ai/engine";
import { isPlainRecord } from "@glassbox-ai/protocol";

const MAX_SIGNALS = 500;
const MAX_SIGNAL_LINE = 1024;
const MAX_SMALL_FILE = 256 * 1024;

/** The spool holds at most this many event files; past it, events are dropped and counted. */
export const SPOOL_MAX_FILES = 5000;
/** hook.log rotates to hook.log.1 at this size (one old file is kept). */
export const LOG_MAX_BYTES = 1024 * 1024;
/** Session folders untouched for longer are removed at SessionStart (metadata retention, Q10). */
export const SESSION_RETENTION_DAYS = 30;

const myUid = (): number | null => (typeof process.getuid === "function" ? process.getuid() : null);

/** A file this user may trust: a regular file (not a link), owned by this user where owners exist. */
function inspect(file: string): "missing" | "unsafe" | fs.Stats {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(file);
  } catch {
    return "missing";
  }
  if (!st.isFile()) return "unsafe";
  const uid = myUid();
  if (uid !== null && st.uid !== uid) return "unsafe";
  return st;
}

/** A file-name-safe id: kept when it is already plain, otherwise hashed. Never contains a path separator or "..". */
export function safeId(id: string): string {
  return /^[A-Za-z0-9_-]{1,128}$/.test(id) ? id : `h${crypto.createHash("sha256").update(String(id)).digest("hex").slice(0, 40)}`;
}

/** An open decision: written at PreToolUse, closed by PostToolUse/Failure/Batch, Stop or SessionEnd. */
export interface PendingDecision {
  callId: string;
  toolName: string;
  agentId: string | null;
  verdict: "allow" | "warn" | "ask" | "deny";
  appliedAs: "allow" | "allow+note" | "ask" | "deny";
  reason: string;
  inputDigest: string;
  summary: Record<string, unknown>;
  actionRisk: { level: "read" | "write-reversible" | "high-risk"; tags: string[]; unanalyzable: boolean };
  /** Signals kept only if the call actually ran (engine: scheduled-job). */
  deferredSignals: SessionSignal[];
  createdAt: string;
  /** Claude Code showed its own permission prompt for this call (PermissionRequest). */
  claudeCodeAsked?: boolean;
}

export class Store {
  constructor(readonly home: string) {}

  private ensureDir(dir: string): void {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  private readSmall(file: string): string | null {
    const st = inspect(file);
    if (typeof st === "string" || st.size > MAX_SMALL_FILE) return null; // no links, others' files or huge files
    try {
      return fs.readFileSync(file, "utf8");
    } catch {
      return null;
    }
  }

  /** `unsafe`: the file exists but is a link or belongs to another user; it is ignored. */
  readJson(name: "config.json" | "remembered.json"): { found: boolean; value: unknown; error: boolean; unsafe: boolean } {
    const file = path.join(this.home, name);
    if (inspect(file) === "unsafe") return { found: true, value: undefined, error: false, unsafe: true };
    const text = this.readSmall(file);
    if (text === null) return { found: false, value: undefined, error: false, unsafe: false };
    try {
      return { found: true, value: JSON.parse(text) as unknown, error: false, unsafe: false };
    } catch {
      return { found: true, value: undefined, error: true, unsafe: false };
    }
  }

  /** True when device-salt exists but can't be trusted (a link or another user's file). */
  saltUnsafe = false;

  /** Random per-device salt for project id hashes; created on first use, owner-only. */
  salt(): Buffer {
    const file = path.join(this.home, "device-salt");
    if (inspect(file) === "unsafe") {
      // Never trust (or overwrite) it: an in-memory salt only changes project ids, which makes
      // remembered rules not match (stricter), and the event says why.
      this.saltUnsafe = true;
      return crypto.randomBytes(32);
    }
    const existing = this.readSmall(file);
    if (existing !== null && /^[0-9a-f]{64}$/.test(existing.trim())) return Buffer.from(existing.trim(), "hex");
    this.ensureDir(this.home);
    const fresh = crypto.randomBytes(32);
    try {
      fs.writeFileSync(file, fresh.toString("hex"), { flag: "wx", mode: 0o600 });
      return fresh;
    } catch {
      // Another hook process created it first: use theirs.
      const again = this.readSmall(file);
      return again !== null && /^[0-9a-f]{64}$/.test(again.trim()) ? Buffer.from(again.trim(), "hex") : fresh;
    }
  }

  /**
   * Linux and macOS: fix group/world-writable state to owner-only and report what was fixed.
   * Windows: nothing here (reading ACLs is too slow for every call; `glassbox doctor` checks them).
   */
  fixPermissions(): string[] {
    if (myUid() === null) return [];
    const fixed: string[] = [];
    const items: [string, number][] = [
      [this.home, 0o700], [path.join(this.home, "spool"), 0o700], [path.join(this.home, "rules"), 0o700],
      [path.join(this.home, "sessions"), 0o700], [path.join(this.home, "logs"), 0o700],
      [path.join(this.home, "config.json"), 0o600], [path.join(this.home, "remembered.json"), 0o600], [path.join(this.home, "device-salt"), 0o600],
    ];
    for (const [p, mode] of items) {
      let st: fs.Stats;
      try {
        st = fs.lstatSync(p);
      } catch {
        continue;
      }
      if (st.isSymbolicLink() || st.uid !== myUid()) continue; // never chmod through a link or someone else's file
      if ((st.mode & 0o077) !== 0) {
        try {
          fs.chmodSync(p, mode);
          fixed.push(path.basename(p));
        } catch {
          // Best effort: the event is still recorded.
        }
      }
    }
    return fixed;
  }

  private sessionDir(sessionId: string): string {
    return path.join(this.home, "sessions", safeId(sessionId));
  }

  readSignals(sessionId: string): SessionSignal[] {
    const text = this.readSmall(path.join(this.sessionDir(sessionId), "signals.jsonl"));
    if (text === null) return [];
    const out: SessionSignal[] = [];
    for (const line of text.split("\n")) {
      if (!line || line.length > MAX_SIGNAL_LINE) continue;
      try {
        const s: unknown = JSON.parse(line);
        if (isPlainRecord(s) && typeof s["kind"] === "string" && typeof s["atCall"] === "number") out.push(s as unknown as SessionSignal);
      } catch {
        // A torn line from a concurrent append: ignore it.
      }
    }
    return out.slice(-MAX_SIGNALS);
  }

  appendSignals(sessionId: string, signals: readonly SessionSignal[]): void {
    const lines = signals.map((s) => JSON.stringify(s)).filter((l) => l.length <= MAX_SIGNAL_LINE);
    if (lines.length === 0) return;
    const dir = this.sessionDir(sessionId);
    this.ensureDir(dir);
    fs.appendFileSync(path.join(dir, "signals.jsonl"), lines.join("\n") + "\n", { mode: 0o600 });
  }

  putPending(sessionId: string, p: PendingDecision): void {
    const dir = path.join(this.sessionDir(sessionId), "pending");
    this.ensureDir(dir);
    fs.writeFileSync(path.join(dir, `${safeId(p.callId)}.json`), JSON.stringify(p), { mode: 0o600 });
  }

  /** Remove and return an open decision (null if none: already closed, or not ours). */
  takePending(sessionId: string, callId: string): PendingDecision | null {
    const file = path.join(this.sessionDir(sessionId), "pending", `${safeId(callId)}.json`);
    const text = this.readSmall(file);
    if (text === null) return null;
    try {
      fs.unlinkSync(file);
    } catch {
      return null; // another process closed it first
    }
    return parsePending(text);
  }

  /** Remove and return every open decision that `match` selects. */
  takeAllPending(sessionId: string, match: (p: PendingDecision) => boolean): PendingDecision[] {
    const dir = path.join(this.sessionDir(sessionId), "pending");
    let names: string[];
    try {
      names = fs.readdirSync(dir);
    } catch {
      return [];
    }
    const out: PendingDecision[] = [];
    for (const n of names.sort()) {
      const file = path.join(dir, n);
      const text = this.readSmall(file);
      const p = text === null ? null : parsePending(text);
      if (p === null || !match(p)) continue;
      try {
        fs.unlinkSync(file);
        out.push(p);
      } catch {
        // closed concurrently
      }
    }
    return out;
  }

  /**
   * Write events as one new spool file (temp file, then rename: readers never see half a file).
   * A full spool (SPOOL_MAX_FILES) drops the events and counts them in spool/dropped.json; a
   * spool folder that is a link is never written into.
   */
  spool(lines: readonly string[]): "written" | "dropped" | "unsafe" {
    if (lines.length === 0) return "written";
    const dir = path.join(this.home, "spool");
    if (!this.safeDir(dir)) return "unsafe";
    this.ensureDir(dir);
    let count = 0;
    try {
      count = fs.readdirSync(dir).filter((n) => n.endsWith(".jsonl")).length;
    } catch {
      // unreadable: try the write anyway
    }
    if (count >= SPOOL_MAX_FILES) {
      this.countDropped(dir, lines.length);
      return "dropped";
    }
    const name = `${Date.now()}-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
    const tmp = path.join(dir, `${name}.tmp`);
    fs.writeFileSync(tmp, lines.join("\n") + "\n", { flag: "wx", mode: 0o600 });
    fs.renameSync(tmp, path.join(dir, `${name}.jsonl`));
    return "written";
  }

  /** A folder that is missing (it will be created) or a real folder of ours, never a link. */
  private safeDir(dir: string): boolean {
    try {
      const st = fs.lstatSync(dir);
      const uid = myUid();
      return st.isDirectory() && !st.isSymbolicLink() && (uid === null || st.uid === uid);
    } catch {
      return true;
    }
  }

  private countDropped(dir: string, n: number): void {
    const file = path.join(dir, "dropped.json");
    let count = 0;
    const text = this.readSmall(file);
    if (text !== null) {
      try {
        const v: unknown = JSON.parse(text);
        if (isPlainRecord(v) && typeof v["count"] === "number" && Number.isSafeInteger(v["count"])) count = v["count"];
      } catch {
        // a broken counter restarts at 0
      }
    }
    try {
      const tmp = path.join(dir, `dropped-${process.pid}-${crypto.randomBytes(4).toString("hex")}.tmp`);
      fs.writeFileSync(tmp, JSON.stringify({ count: count + n, last: new Date(Date.now()).toISOString() }), { flag: "wx", mode: 0o600 });
      fs.renameSync(tmp, file);
    } catch {
      // a lost increment is acceptable
    }
  }

  /** One line in logs/hook.log (rotated to hook.log.1 at LOG_MAX_BYTES). Callers pass no content. */
  log(entry: Record<string, unknown>): void {
    const dir = path.join(this.home, "logs");
    if (!this.safeDir(dir)) return;
    this.ensureDir(dir);
    const file = path.join(dir, "hook.log");
    try {
      const st = fs.lstatSync(file);
      if (st.isSymbolicLink()) return;
      if (st.size >= LOG_MAX_BYTES) {
        const old = path.join(dir, "hook.log.1");
        try {
          fs.renameSync(file, old);
        } catch {
          fs.rmSync(old, { force: true });
          fs.renameSync(file, old);
        }
      }
    } catch {
      // no log yet
    }
    fs.appendFileSync(file, JSON.stringify(entry) + "\n", { mode: 0o600 });
  }

  /**
   * Claude Code showed its own permission prompt (PermissionRequest has no tool_use_id): mark
   * the open decisions of the same tool with exactly the same input (and agent) as asked.
   */
  markClaudeCodeAsked(sessionId: string, toolName: string, inputDigest: string, agentId: string | null): number {
    const dir = path.join(this.sessionDir(sessionId), "pending");
    let names: string[];
    try {
      names = fs.readdirSync(dir);
    } catch {
      return 0;
    }
    let marked = 0;
    for (const n of names) {
      const file = path.join(dir, n);
      const text = this.readSmall(file);
      const p = text === null ? null : parsePending(text);
      if (p === null || p.toolName !== toolName || p.inputDigest !== inputDigest || p.agentId !== agentId) continue;
      try {
        fs.writeFileSync(file, JSON.stringify({ ...p, claudeCodeAsked: true }), { mode: 0o600 });
        marked++;
      } catch {
        // closed concurrently
      }
    }
    return marked;
  }

  /**
   * Remove session folders untouched for SESSION_RETENTION_DAYS. A link is removed as a link
   * (what it points to is never touched); real folders are removed with their contents.
   */
  pruneSessions(nowMs: number): number {
    const root = path.join(this.home, "sessions");
    if (!this.safeDir(root)) return 0;
    let names: string[];
    try {
      names = fs.readdirSync(root);
    } catch {
      return 0;
    }
    const cutoff = nowMs - SESSION_RETENTION_DAYS * 86_400_000;
    let removed = 0;
    for (const n of names) {
      const p = path.join(root, n);
      try {
        const st = fs.lstatSync(p);
        if (st.isSymbolicLink()) {
          try {
            fs.unlinkSync(p);
          } catch {
            fs.rmdirSync(p); // a Windows junction
          }
          removed++;
          continue;
        }
        if (!st.isDirectory()) continue;
        const newest = Math.max(st.mtimeMs, ...["signals.jsonl", "pending"].map((c) => {
          try {
            return fs.lstatSync(path.join(p, c)).mtimeMs;
          } catch {
            return 0;
          }
        }));
        if (newest < cutoff) {
          fs.rmSync(p, { recursive: true, force: true });
          removed++;
        }
      } catch {
        // skip what can't be read
      }
    }
    return removed;
  }
}

function parsePending(text: string): PendingDecision | null {
  try {
    const p: unknown = JSON.parse(text);
    if (!isPlainRecord(p) || typeof p["callId"] !== "string" || typeof p["verdict"] !== "string" || typeof p["reason"] !== "string") return null;
    return p as unknown as PendingDecision;
  } catch {
    return null;
  }
}
