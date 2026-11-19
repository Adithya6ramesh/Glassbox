// Accumulator for action classification results (shared by shell, PowerShell, SQL, tools).
import type { ActionRiskLevel, ActionTag } from "../types.js";
import { JOB_LABEL, type JobKind, type ScheduledJob } from "./schedule.js";

export interface CodeFinding { ruleId: string; note?: string }

export class Acc {
  level: ActionRiskLevel = "read";
  tags = new Set<ActionTag>();
  unanalyzableReasons: string[] = [];
  selfProtection = false;
  findings: CodeFinding[] = [];
  reasons: string[] = [];
  sensitive: string[] = [];
  network = false;
  sensitiveArgs = false;
  /** Prints the whole environment (env, printenv, set, export -p): harmless alone, exfiltration next to a network call. */
  envDump = false;
  /** Git remotes added or repointed in this command, and push destinations (CP-EXFIL-034). */
  newRemotes: string[] = [];
  /** Local files this command uploads, by kind (upload.ts). */
  uploads: ("sensitive" | "outside" | "project")[] = [];
  /** Scheduled jobs this command creates, changes or removes (schedule.ts). */
  scheduledJobs: ScheduledJob[] = [];
  /** Normalized paths this command writes, moves or deletes. */
  writes: string[] = [];
  pushedTo: string[] = [];
  /** Paths read that are sensitive (for signals); labels only. */

  raise(level: ActionRiskLevel): void {
    const order: ActionRiskLevel[] = ["read", "write-reversible", "high-risk"];
    if (order.indexOf(level) > order.indexOf(this.level)) this.level = level;
  }

  tag(level: ActionRiskLevel, ...tags: ActionTag[]): void {
    this.raise(level);
    for (const t of tags) this.tags.add(t);
  }

  unanalyzable(reason: string): void {
    if (!this.unanalyzableReasons.includes(reason) && this.unanalyzableReasons.length < 10) this.unanalyzableReasons.push(reason);
    this.raise("high-risk");
    this.find("CP-SHELL-001", reason);
  }

  protect(ruleId: "CP-SELF-001" | "CP-SELF-002" | "CP-SELF-003" | "CP-SELF-004", reason: string): void {
    this.selfProtection = true;
    this.raise("high-risk");
    this.tags.add("self-protection");
    this.find(ruleId, reason);
    this.reason(reason);
  }

  /** A write or delete of a persistence location: protected (deny) or a CP-SELF-005 ask. */
  persist(hit: { kind: "deny" | "ask" | "job"; label: string; job?: JobKind } | null, verb: "changes" | "deletes", path: string | null = null): void {
    if (hit === null) return;
    const why = `${verb} a ${hit.label}`;
    if (hit.kind === "deny") { this.protect("CP-SELF-004", why); return; }
    if (hit.kind === "job" && hit.job) {
      // The job file itself is recorded: it runs (Startup folder, cron.daily, init.d) or defines the job.
      this.scheduleJob({ kind: hit.job, verb: verb === "deletes" ? "removes" : "changes", path, schedule: null, files: verb === "deletes" || path === null ? [] : [path] });
      return;
    }
    this.tag("high-risk", "config.agent");
    this.find("CP-SELF-005", why);
    this.reason(why);
  }

  /** Creating, changing or removing a scheduled job: CP-SELF-006 (ask; deny in autopilot). */
  scheduleJob(job: ScheduledJob): void {
    this.tag("high-risk", "infra.change");
    const why = `${job.verb} a ${JOB_LABEL[job.kind]}`;
    this.find("CP-SELF-006", why);
    this.reason(why);
    if (this.scheduledJobs.length < 20) this.scheduledJobs.push(job);
  }

  /** A path this command writes, moves or deletes (for CP-SELF-007). */
  wrote(path: string | null): void {
    if (path !== null && this.writes.length < 200 && !this.writes.includes(path)) this.writes.push(path);
  }

  find(ruleId: string, note?: string): void {
    if (!this.findings.some((f) => f.ruleId === ruleId)) this.findings.push(note === undefined ? { ruleId } : { ruleId, note });
  }

  reason(r: string): void {
    if (!this.reasons.includes(r) && this.reasons.length < 20) this.reasons.push(r);
  }

  merge(o: Acc): void {
    this.raise(o.level);
    for (const t of o.tags) this.tags.add(t);
    for (const r of o.unanalyzableReasons) if (!this.unanalyzableReasons.includes(r)) this.unanalyzableReasons.push(r);
    if (o.selfProtection) this.selfProtection = true;
    for (const f of o.findings) this.find(f.ruleId, f.note);
    for (const r of o.reasons) this.reason(r);
    this.sensitive.push(...o.sensitive);
    this.network ||= o.network;
    this.sensitiveArgs ||= o.sensitiveArgs;
    this.envDump ||= o.envDump;
    this.newRemotes.push(...o.newRemotes);
    this.uploads.push(...o.uploads);
    for (const j of o.scheduledJobs) if (this.scheduledJobs.length < 20) this.scheduledJobs.push(j);
    for (const w of o.writes) this.wrote(w);
    this.pushedTo.push(...o.pushedTo);
  }

  get unanalyzableFlag(): boolean {
    return this.unanalyzableReasons.length > 0;
  }
}
