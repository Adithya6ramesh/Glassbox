// Uploads of local files (spec rev 8, Q1). Shared by the bash and PowerShell analyzers.
//  - a sensitive file (secrets, .env, keys, ~/.ssh)     → ask (CP-EXFIL-030)
//  - a file outside the project, or one not known statically → ask (CP-EXFIL-035)
//  - any upload after the session read untrusted content → ask (CP-EXFIL-036, in the gate)
//  - other project files → warn (high-risk net.egress, as any network call)
//  - every destination on this machine (localhost, 127.0.0.0/8, ::1) → not egress at all
import type { Acc } from "./acc.js";
import { isProtectedRead, normalizeFull, normalizePath, sensitiveLabel, type NormPath, type PathCtx } from "./paths.js";

export type UploadKind = "sensitive" | "outside" | "project";

/** True for loopback host names and addresses. */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost") || h === "::1" || h === "0.0.0.0") return true;
  const parts = h.split(".");
  return parts.length === 4 && parts[0] === "127" && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/**
 * The host of a URL, a bare host[:port][/path], or user@host:path. Null when there is none
 * (for example a value with no host-like start). String code only.
 */
export function hostOf(v: string): string | null {
  let s = v.trim();
  const scheme = s.indexOf("://");
  if (scheme > 0) s = s.slice(scheme + 3);
  const at = s.indexOf("@");
  const slash = s.indexOf("/");
  if (at >= 0 && (slash < 0 || at < slash)) s = s.slice(at + 1);
  if (s.startsWith("[")) { const end = s.indexOf("]"); return end > 0 ? s.slice(0, end + 1) : null; }
  let end = s.length;
  for (const ch of [":", "/", "?", "#"]) { const i = s.indexOf(ch); if (i >= 0 && i < end) end = i; }
  const host = s.slice(0, end);
  return host.length > 0 ? host : null;
}

/** Destinations are known and all on this machine. */
export function allLoopback(destinations: readonly (string | null)[]): boolean {
  if (destinations.length === 0) return false;
  return destinations.every((d) => d !== null && (() => { const h = hostOf(d); return h !== null && isLoopbackHost(h); })());
}

/**
 * Windows paths whose meaning differs from their lexical form: UNC shares (also \\localhost\C$),
 * and the \\?\ (literal: ".." is not collapsed) and \\.\ (device) namespaces. An upload from
 * such a path is never shown to be a project file.
 */
const WIN_SPECIAL_PREFIX = /^[\\/]{2}/;
/** `C:notes.txt` is relative to drive C's own current directory, not to the project. */
const WIN_DRIVE_RELATIVE = /^[A-Za-z]:(?![\\/])/;

/**
 * Classifies an uploaded file. `projectDir` is the session's project directory (raw, as the
 * caller gave it); `raw` is the file argument as written. Since 0.1.2 the project directory is
 * normalized like the file path (before, on Windows every upload counted as "outside").
 */
export function classifyUpload(np: NormPath | null, pctx: PathCtx, projectDir: string | null, raw?: string | null): UploadKind {
  if (np === null || np.path === null) {
    if (np !== null && sensitiveLabel(np, pctx)) return "sensitive";
    return "outside"; // not known statically: it can't be shown to be a project file
  }
  if (isProtectedRead(np, pctx) || sensitiveLabel(np, pctx)) return "sensitive";

  // Where the path really leads, when the caller resolved it (junctions, symlinks).
  const resolved = pctx.resolved?.[np.path];
  const real = resolved === undefined ? null : normalizePath(resolved, { ...pctx, cwd: null, resolved: undefined });
  if (real !== null && real.path !== null && (isProtectedRead(real, pctx) || sensitiveLabel(real, pctx))) return "sensitive";

  if (projectDir === null) return "outside";
  if (pctx.platform === "win32" && typeof raw === "string" && (WIN_SPECIAL_PREFIX.test(raw.trim()) || WIN_DRIVE_RELATIVE.test(raw.trim()))) return "outside";
  const rootFull = normalizeFull(projectDir, { ...pctx, cwd: null });
  if (rootFull === null) return "outside";
  const root = rootFull.length > 1 && rootFull.endsWith("/") ? rootFull.slice(0, -1) : rootFull;
  const inside = (p: string) => p === root || p.startsWith(root.endsWith("/") ? root : root + "/");
  if (!inside(np.path)) return "outside";
  if (real !== null && (real.path === null || !inside(real.path))) return "outside";
  return "project";
}

/** Records one uploaded file (the caller has checked the destination isn't loopback). */
export function recordUpload(acc: Acc, kind: UploadKind, what: string): void {
  acc.uploads.push(kind);
  acc.tag("high-risk", "net.egress");
  acc.network = true;
  if (kind === "sensitive") {
    acc.sensitiveArgs = true;
    acc.find("CP-EXFIL-030", `uploads a sensitive file (${what})`);
  } else if (kind === "outside") {
    acc.find("CP-EXFIL-035", `uploads a file from outside the project, or one that isn't known statically (${what})`);
  }
  acc.reason(`uploads a local file (${what})`);
}
