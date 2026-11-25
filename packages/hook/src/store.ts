// Local state under ~/.glassbox (the engine denies the agent any write there).
//
//   config.json                    mode + experimental flags (written by the CLI)
//   remembered.json                "allow & remember" rules (written by the CLI)
//   device-salt                    random salt for project id hashes
//   sessions/<sid>/signals.jsonl   engine session signals, append-only
//   sessions/<sid>/pending/<id>    one open decision per tool call, closed by a later event
//   spool/<ts>-<pid>-<rand>.jsonl  events for the uploader, written whole then renamed
//
// Parallel tool calls run parallel hook processes, so nothing here is a shared read-modify-
// write file: one file per decision, one spool file per process, single-call appends.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { SessionSignal } from "@glassbox-ai/engine";
import { isPlainRecord } from "@glassbox-ai/protocol";

const MAX_SIGNALS = 500;
const MAX_SIGNAL_LINE = 1024;
const MAX_SMALL_FILE = 256 * 1024;

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
}

export class Store {
  constructor(readonly home: string) {}

  private ensureDir(dir: string): void {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  private readSmall(file: string): string | null {
    try {
      const st = fs.lstatSync(file);
      if (!st.isFile() || st.size > MAX_SMALL_FILE) return null; // no symlinks, no huge files
      return fs.readFileSync(file, "utf8");
    } catch {
      return null;
    }
  }

  readJson(name: "config.json" | "remembered.json"): { found: boolean; value: unknown; error: boolean } {
    const text = this.readSmall(path.join(this.home, name));
    if (text === null) return { found: false, value: undefined, error: false };
    try {
      return { found: true, value: JSON.parse(text) as unknown, error: false };
    } catch {
      return { found: true, value: undefined, error: true };
    }
  }

  /** Random per-device salt for project id hashes; created on first use, owner-only. */
  salt(): Buffer {
    const file = path.join(this.home, "device-salt");
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

  /** Write events as one new spool file (temp file, then rename: readers never see half a file). */
  spool(lines: readonly string[]): void {
    if (lines.length === 0) return;
    const dir = path.join(this.home, "spool");
    this.ensureDir(dir);
    const name = `${Date.now()}-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
    const tmp = path.join(dir, `${name}.tmp`);
    fs.writeFileSync(tmp, lines.join("\n") + "\n", { flag: "wx", mode: 0o600 });
    fs.renameSync(tmp, path.join(dir, `${name}.jsonl`));
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
