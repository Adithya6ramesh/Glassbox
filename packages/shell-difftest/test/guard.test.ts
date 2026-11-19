// The T-DIFF location guard (decided 2026-11-19): never on a developer's machine; only in
// Linux CI, or in a Docker container with no network and no mounted folders.
// These tests run everywhere (they never start bash).
import { describe, expect, it } from "vitest";
import { tdiffAllowed, type GuardProbe } from "../src/guard.js";
import { findBash, runInBash } from "../src/harness.js";

const CLEAN_MOUNTINFO = [
  "100 90 0:50 / / rw,relatime - overlay overlay rw",
  "101 100 0:52 / /proc rw - proc proc rw",
  "102 100 0:53 / /dev rw - tmpfs tmpfs rw",
  "103 102 0:54 / /dev/pts rw - devpts devpts rw",
  "104 100 0:55 / /sys ro - sysfs sysfs ro",
  "105 104 0:26 / /sys/fs/cgroup ro - cgroup2 cgroup rw",
  "106 100 8:1 /var/lib/docker/containers/x/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw",
  "107 100 8:1 /var/lib/docker/containers/x/hostname /etc/hostname rw - ext4 /dev/sda1 rw",
  "108 100 8:1 /var/lib/docker/containers/x/hosts /etc/hosts rw - ext4 /dev/sda1 rw",
].join("\n");

function probe(over: Partial<GuardProbe> & { files?: Record<string, string>; dirs?: Record<string, string[]> } = {}): GuardProbe {
  const files = over.files ?? {};
  const dirs = over.dirs ?? {};
  return {
    platform: over.platform ?? "linux",
    env: over.env ?? {},
    exists: (p) => p in files || p in dirs,
    readFile: (p) => files[p] ?? null,
    listDir: (p) => dirs[p] ?? null,
  };
}

const sandbox = (extra: { mountinfo?: string; ifaces?: string[]; dockerenv?: boolean; env?: Record<string, string> } = {}) =>
  probe({
    env: extra.env ?? { GLASSBOX_TDIFF_SANDBOX: "docker" },
    files: { "/proc/self/mountinfo": extra.mountinfo ?? CLEAN_MOUNTINFO, ...(extra.dockerenv === false ? {} : { "/.dockerenv": "" }) },
    dirs: { "/sys/class/net": extra.ifaces ?? ["lo"] },
  });

describe("T-DIFF location guard", () => {
  it("refuses on Windows and macOS, whatever the environment says", () => {
    for (const platform of ["win32", "darwin"]) {
      expect(tdiffAllowed(probe({ platform, env: { GITHUB_ACTIONS: "true", CI: "true", GLASSBOX_TDIFF_SANDBOX: "docker", GLASSBOX_BASH: "C:/Program Files/Git/usr/bin/bash.exe" } })).allowed).toBe(false);
    }
  });

  it("refuses on a plain Linux machine (not CI, not the sandbox)", () => {
    expect(tdiffAllowed(probe({ env: { GLASSBOX_BASH: "/bin/bash" } })).allowed).toBe(false);
    expect(tdiffAllowed(probe({ env: { CI: "true" } })).allowed).toBe(false);
  });

  it("allows GitHub Actions on Linux", () => {
    expect(tdiffAllowed(probe({ env: { GITHUB_ACTIONS: "true", CI: "true" } })).allowed).toBe(true);
  });

  it("allows the Docker sandbox only with no network and no mounted folders", () => {
    expect(tdiffAllowed(sandbox()).allowed).toBe(true);
    expect(tdiffAllowed(sandbox({ ifaces: ["lo", "eth0"] })).allowed).toBe(false);
    expect(tdiffAllowed(sandbox({ mountinfo: CLEAN_MOUNTINFO + "\n200 100 8:1 /home/me/code /repo rw - ext4 /dev/sda1 rw" })).allowed).toBe(false);
    expect(tdiffAllowed(sandbox({ mountinfo: CLEAN_MOUNTINFO + "\n201 100 0:60 / /var/run/docker.sock rw - tmpfs tmpfs rw" })).allowed).toBe(false);
    expect(tdiffAllowed(sandbox({ dockerenv: false })).allowed).toBe(false);
    expect(tdiffAllowed(sandbox({ env: {} })).allowed).toBe(false);
  });

  it("refuses when the container can't be inspected", () => {
    expect(tdiffAllowed(probe({ env: { GLASSBOX_TDIFF_SANDBOX: "docker" }, files: { "/.dockerenv": "" } })).allowed).toBe(false);
  });

  it("in Linux CI, T-DIFF really runs (a silent skip there fails the build)", () => {
    if (!(process.env["GITHUB_ACTIONS"] === "true" && process.env["CI"] === "true" && process.platform === "linux")) return;
    expect(findBash()).toBe("/bin/bash");
  });

  it("on this machine, unless it is CI or the sandbox, no bash is offered and runInBash refuses", async () => {
    const inCI = process.env["GITHUB_ACTIONS"] === "true" && process.platform === "linux";
    const inSandbox = process.env["GLASSBOX_TDIFF_SANDBOX"] === "docker" && process.platform === "linux";
    if (inCI || inSandbox) return;
    expect(findBash()).toBeUndefined();
    await expect(runInBash("/bin/bash", "echo hi")).rejects.toThrow(/refuses to run/);
  });
});
