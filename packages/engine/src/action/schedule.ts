// Scheduled jobs (spec rev 9): cron, systemd timers and units, at, launchd, XDG autostart, the
// Windows Startup folder, Task Scheduler and services. Creating, changing or removing one asks
// (CP-SELF-006, deny in autopilot) and the ask shows the schedule and the full command. The
// files a job runs are recorded as a session signal; later agent edits, moves or deletes of
// those files ask too (CP-SELF-007). String code only: no regex with nested quantifiers.

export type JobKind = "cron" | "systemd" | "at" | "launchd" | "autostart" | "startup-folder" | "task-scheduler" | "service" | "boot-script";

/**
 * Windows registry keys that start a program at login (rev 11): ...\CurrentVersion\Run, RunOnce,
 * RunOnceEx, RunServices[Once], in HKCU/HKLM and the 32-bit view (WOW6432Node), and the Explorer
 * policy Run key. Compared with separators, quotes and spaces removed, case-insensitively; any
 * key whose name starts with "Run" right under CurrentVersion counts (conservative: ask).
 */
export function isRunKey(text: string): boolean {
  const s = text.toLowerCase().replace(/[\\/"'\s`]/g, "");
  return /microsoftwindowscurrentversion(policiesexplorer)?run/.test(s);
}

export interface ScheduledJob {
  kind: JobKind;
  verb: "creates" | "changes" | "removes";
  /** The job definition file, when the job is a file (a unit, plist, .desktop, cron.d entry…). */
  path: string | null;
  /** How often or when it runs, as written; null when it isn't known statically. */
  schedule: string | null;
  /** Files the job runs (programs and scripts), as written in the command or file. */
  files: string[];
}

export const JOB_LABEL: Record<JobKind, string> = {
  cron: "cron job",
  systemd: "systemd unit or timer",
  at: "one-off job (at)",
  launchd: "launchd agent or daemon",
  autostart: "login autostart entry",
  "startup-folder": "Windows Startup folder entry",
  "task-scheduler": "Windows scheduled task",
  service: "service",
  "boot-script": "boot script",
};

const CRON_MACROS = new Set(["@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"]);
const isCronField = (t: string) => t.length > 0 && t.length <= 40 && [...t].every((ch) => "0123456789*/,-".includes(ch) || (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z"));

/** Cron lines in free text (a crontab file, or `echo '* * * * * cmd' | crontab -`). */
export function cronLines(text: string): { schedule: string; command: string }[] {
  const out: { schedule: string; command: string }[] = [];
  // Split on newlines and on quote characters, so quoted echo arguments become lines.
  const parts: string[] = [];
  let cur = "";
  for (const ch of text.slice(0, 20_000)) {
    if (ch === "\n" || ch === "'" || ch === '"' || ch === "`") { parts.push(cur); cur = ""; } else cur += ch;
  }
  parts.push(cur);
  for (const raw of parts) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const toks = line.split(/\s+/);
    if (toks[0] !== undefined && CRON_MACROS.has(toks[0].toLowerCase()) && toks.length > 1) {
      out.push({ schedule: toks[0], command: toks.slice(1).join(" ") });
    } else if (toks.length > 5 && toks.slice(0, 5).every(isCronField) && toks.slice(0, 5).some((t) => t.includes("*") || /\d/.test(t))) {
      // Skip "VAR=value" environment lines and words that only look like fields.
      if (toks[0]?.includes("=")) continue;
      out.push({ schedule: toks.slice(0, 5).join(" "), command: toks.slice(5).join(" ") });
    }
    if (out.length >= 20) break;
  }
  return out;
}

/** Strips leading `"'(` and trailing `"');,` without a regex (a trailing `[…]+$` is quadratic in V8). */
function cleanToken(t: string): string {
  let a = 0, b = t.length;
  while (a < b && "\"'(".includes(t[a] as string)) a++;
  while (b > a && "\"');,".includes(t[b - 1] as string)) b--;
  return t.slice(a, b);
}

const INTERPRETERS = new Set(["sh", "bash", "zsh", "dash", "python", "python3", "node", "perl", "ruby", "powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe", "env", "wscript", "cscript", "nohup", "sudo"]);
const SCRIPT_EXT = [".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".js", ".mjs", ".ps1", ".bat", ".cmd", ".exe", ".vbs", ".lnk", ".jar", ".php"];

/** Program and script paths in a command line: anything path-like or with a script extension. */
export function commandFiles(command: string): string[] {
  const out: string[] = [];
  for (const raw of command.trim().split(/\s+/).slice(0, 200)) {
    const t = cleanToken(raw);
    if (t === "" || t.includes("://") || t.startsWith("-")) continue;
    if (t.length === 2 && t.startsWith("/")) continue; // cmd-style switches like /c
    if (INTERPRETERS.has(t.toLowerCase()) || INTERPRETERS.has(t.slice(t.lastIndexOf("/") + 1).toLowerCase())) continue;
    const lower = t.toLowerCase();
    if (t.includes("/") || t.includes("\\") || SCRIPT_EXT.some((e) => lower.endsWith(e))) out.push(t);
    if (out.length >= 8) break;
  }
  return [...new Set(out)];
}

function between(text: string, open: string, close: string, from = 0): { value: string; end: number } | null {
  const a = text.indexOf(open, from);
  if (a < 0) return null;
  const b = text.indexOf(close, a + open.length);
  if (b < 0) return null;
  return { value: text.slice(a + open.length, b).trim(), end: b + close.length };
}

/** A launchd plist: ProgramArguments/Program and StartInterval, StartCalendarInterval, RunAtLoad… */
export function plistJob(xml: string): { schedule: string | null; files: string[] } {
  const text = xml.slice(0, 200_000);
  const files: string[] = [];
  const keyAt = (k: string) => text.indexOf(`<key>${k}</key>`);
  const prog = keyAt("Program");
  if (prog >= 0) { const s = between(text, "<string>", "</string>", prog); if (s) files.push(s.value); }
  const pa = keyAt("ProgramArguments");
  if (pa >= 0) {
    const arr = between(text, "<array>", "</array>", pa);
    if (arr) {
      let pos = 0;
      for (let n = 0; n < 8; n++) { const s = between(arr.value, "<string>", "</string>", pos); if (!s) break; files.push(s.value); pos = s.end; }
    }
  }
  const sched: string[] = [];
  const si = keyAt("StartInterval");
  if (si >= 0) { const v = between(text, "<integer>", "</integer>", si); if (v) sched.push(`every ${v.value} s`); }
  if (keyAt("StartCalendarInterval") >= 0) sched.push("on a calendar schedule (StartCalendarInterval)");
  const ral = keyAt("RunAtLoad");
  if (ral >= 0 && text.slice(ral, ral + 40).includes("<true/>")) sched.push("at load and login");
  if (keyAt("KeepAlive") >= 0) sched.push("kept alive");
  if (keyAt("WatchPaths") >= 0) sched.push("when watched paths change");
  return { schedule: sched.length > 0 ? sched.join(", ") : null, files: [...new Set([...commandFiles(files.slice(0, 1).join(" ")), ...files.slice(1).filter((f) => f.includes("/"))])] };
}

/** INI-style files: systemd units and .desktop autostart entries. */
function iniValues(text: string, keys: string[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of text.slice(0, 200_000).split("\n").slice(0, 2000)) {
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const k = line.slice(0, eq).trim();
    if (keys.includes(k)) (out[k] ??= []).push(line.slice(eq + 1).trim());
  }
  return out;
}

export function unitJob(text: string): { schedule: string | null; files: string[] } {
  const v = iniValues(text, ["ExecStart", "ExecStartPre", "ExecStartPost", "OnCalendar", "OnBootSec", "OnStartupSec", "OnUnitActiveSec", "OnUnitInactiveSec", "OnActiveSec", "WantedBy"]);
  const files = (v["ExecStart"] ?? []).concat(v["ExecStartPre"] ?? [], v["ExecStartPost"] ?? []).flatMap((c) => commandFiles(c.replace(/^[-@:+!]+/, "")));
  const sched = ["OnCalendar", "OnBootSec", "OnStartupSec", "OnUnitActiveSec", "OnUnitInactiveSec", "OnActiveSec"].flatMap((k) => (v[k] ?? []).map((x) => `${k}=${x}`));
  if (sched.length === 0 && (v["WantedBy"] ?? []).length > 0) sched.push(`when ${(v["WantedBy"] ?? []).join(", ")} starts`);
  return { schedule: sched.length > 0 ? sched.join(", ") : null, files: [...new Set(files)] };
}

export function desktopJob(text: string): { schedule: string | null; files: string[] } {
  const v = iniValues(text, ["Exec"]);
  return { schedule: "at login", files: [...new Set((v["Exec"] ?? []).flatMap((c) => commandFiles(c)))] };
}

/** schtasks /create arguments → schedule and the program it runs. */
export function schtasksJob(vals: string[]): { schedule: string | null; files: string[] } {
  const get = (flag: string) => { const i = vals.findIndex((v) => v.toLowerCase() === flag); return i >= 0 ? vals[i + 1] ?? null : null; };
  const sched = [["/sc", "schedule"], ["/mo", "modifier"], ["/d", "days"], ["/st", "start time"], ["/sd", "start date"], ["/ri", "repeat every (min)"]]
    .map(([f, label]) => { const v = get(f as string); return v ? `${label} ${v}` : null; }).filter((x): x is string => x !== null);
  const tr = get("/tr");
  return { schedule: sched.length > 0 ? sched.join(", ") : null, files: tr ? commandFiles(tr) : [] };
}

/** Register-ScheduledTask scripts: New-ScheduledTaskAction -Execute/-Argument and New-ScheduledTaskTrigger. */
export function psTaskJob(script: string): { schedule: string | null; files: string[] } {
  const text = script.slice(0, 50_000);
  const lower = text.toLowerCase();
  const files: string[] = [];
  const valueAfter = (from: number, param: string): string | null => {
    const i = lower.indexOf(param, from);
    if (i < 0) return null;
    let j = i + param.length;
    while (j < text.length && (text[j] === " " || text[j] === "\t")) j++;
    const q = text[j];
    if (q === '"' || q === "'") { const e = text.indexOf(q, j + 1); return e > j ? text.slice(j + 1, e) : null; }
    let e = j;
    while (e < text.length && !" \t\n;)".includes(text[e] as string)) e++;
    return text.slice(j, e) || null;
  };
  let pos = 0;
  for (let n = 0; n < 5; n++) {
    const a = lower.indexOf("new-scheduledtaskaction", pos);
    if (a < 0) break;
    const exe = valueAfter(a, "-execute");
    const arg = valueAfter(a, "-argument");
    files.push(...commandFiles(`${exe ?? ""} ${arg ?? ""}`));
    pos = a + 1;
  }
  const t = lower.indexOf("new-scheduledtasktrigger");
  let schedule: string | null = null;
  if (t >= 0) {
    let end = text.indexOf("\n", t);
    if (end < 0) end = text.length;
    const semi = text.indexOf(";", t);
    if (semi >= 0 && semi < end) end = semi;
    schedule = text.slice(t + "new-scheduledtasktrigger".length, Math.min(end, t + 300)).trim() || null;
  }
  return { schedule, files: [...new Set(files)] };
}
