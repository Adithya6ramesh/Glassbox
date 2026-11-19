// Where T-DIFF may run (decided 2026-11-19): never on a developer's machine. Only on Linux,
// and only (a) in GitHub Actions CI, or (b) inside a Docker container that was started as
// the T-DIFF sandbox, with no network interface other than loopback and no host folders
// mounted. Everything else is refused, even when a bash is available.
//
// The decision is a pure function of a probe, so it can be tested on any OS.

export interface GuardProbe {
  platform: string;
  env: Readonly<Record<string, string | undefined>>;
  exists(path: string): boolean;
  readFile(path: string): string | null;
  listDir(path: string): string[] | null;
}

export interface GuardDecision { allowed: boolean; reason: string }

/** Mount points a plain container has. Anything else counts as a mounted folder. */
const STANDARD_MOUNTS = new Set(["/", "/proc", "/sys", "/dev", "/dev/pts", "/dev/mqueue", "/dev/shm", "/sys/fs/cgroup", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/dev/console"]);
const STANDARD_PREFIXES = ["/proc/", "/sys/", "/dev/"];

export function tdiffAllowed(p: GuardProbe): GuardDecision {
  if (p.platform !== "linux") return { allowed: false, reason: `T-DIFF never runs on ${p.platform}; it runs in Linux CI or in the Docker sandbox` };
  if (p.env["GITHUB_ACTIONS"] === "true" && p.env["CI"] === "true") return { allowed: true, reason: "GitHub Actions CI" };
  if (p.env["GLASSBOX_TDIFF_SANDBOX"] !== "docker") return { allowed: false, reason: "not CI and not the Docker sandbox (set by packages/shell-difftest/docker)" };
  if (!p.exists("/.dockerenv")) return { allowed: false, reason: "GLASSBOX_TDIFF_SANDBOX=docker but this isn't a Docker container" };
  const ifaces = p.listDir("/sys/class/net");
  if (ifaces === null) return { allowed: false, reason: "can't list network interfaces" };
  const extra = ifaces.filter((i) => i !== "lo");
  if (extra.length > 0) return { allowed: false, reason: `container has network interfaces (${extra.join(", ")}); run it with --network none` };
  const mountinfo = p.readFile("/proc/self/mountinfo");
  if (mountinfo === null) return { allowed: false, reason: "can't read mountinfo" };
  for (const line of mountinfo.split("\n")) {
    const fields = line.split(" ");
    const mountPoint = fields[4];
    if (!mountPoint) continue;
    if (STANDARD_MOUNTS.has(mountPoint) || STANDARD_PREFIXES.some((x) => mountPoint.startsWith(x))) continue;
    return { allowed: false, reason: `a folder is mounted into the container (${mountPoint}); run it without -v/--mount` };
  }
  return { allowed: true, reason: "Docker sandbox (no network, no mounts)" };
}
