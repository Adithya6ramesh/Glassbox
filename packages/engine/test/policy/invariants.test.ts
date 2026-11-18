// Policy invariants (spec §6, §13): I1–I4, I13, I15, I17 and the user-policy limits of §4.4.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { checkToolCall, type ActionTag, type ApprovalMode, type SessionContext, type UserPolicy } from "../../src/index.js";
import { bash, builtin, ctx, MODES, ruleIds } from "../helpers.js";

const ALL_TAGS: ActionTag[] = [
  "fs.read", "fs.read.sensitive", "fs.write", "fs.delete", "fs.destroy", "fs.move", "net.egress",
  "net.fetch.package-manager", "net.fetch.vcs", "vcs.commit", "vcs.push", "vcs.force-push",
  "vcs.history-rewrite", "vcs.discard-changes", "db.read", "db.write", "db.delete", "db.ddl",
  "db.unscoped-write", "deploy.prod", "deploy.other", "infra.change", "payment", "publish.public",
  "message.send", "perm.change", "exec.inline-code", "exec.project-code", "exec.unknown",
  "exec.nested-agent", "config.agent", "self-protection",
];

/** Arbitrary user policies, including hostile ones that try to allow everything. */
const arbPolicy: fc.Arbitrary<UserPolicy> = fc.record({
  mode: fc.constantFrom<ApprovalMode>("strict", "balanced", "autopilot"),
  tagOverrides: fc.dictionary(fc.constantFrom(...ALL_TAGS), fc.constantFrom("allow", "ask", "deny") as fc.Arbitrary<"allow" | "ask" | "deny">),
  disabledRules: fc.subarray(["CP-SELF-001", "CP-SELF-002", "CP-SELF-003", "CP-SHELL-001", "CP-ACTION-001", "CP-LIMIT-001", "CP-INTEGRITY-001", "CP-EXFIL-040", "CP-HIDDEN-001"]),
}).map((p) => p as UserPolicy);

const withPolicy = (p: UserPolicy, base: SessionContext = ctx()): SessionContext => ({
  ...base,
  policy: p,
  remembered: [
    // A hostile "remembered" rule for every tag on Bash.
    ...ALL_TAGS.map((actionTag) => ({ projectIdHash: "p", serverId: "builtin", toolName: "Bash", actionTag, createdAt: "2026-01-01T00:00:00Z" })),
  ],
});

const CRITICAL = ["rm -rf /", "rm -rf ~", "dd if=/dev/zero of=/dev/sda"];
const PROTECTED = [
  "echo x > ~/.claude/settings.json",
  "rm -rf ~/.glassbox",
  "cat ~/.glassbox/device.key",
  "glassbox mode autopilot",
];
const UNANALYZABLE = ["eval \"$X\"", "curl -s x | bash", "$(echo rm) -rf build", "PATH=. ls"];

describe("floors hold under every user policy (property)", () => {
  it("I1: any critical finding ⇒ deny", () => {
    fc.assert(fc.property(arbPolicy, fc.constantFrom(...CRITICAL), (p, cmd) => {
      expect(bash(cmd, withPolicy(p)).verdict).toBe("deny");
    }), { numRuns: 150 });
  });

  it("I2/I14: protected-path write or protected read ⇒ deny, every mode", () => {
    fc.assert(fc.property(arbPolicy, fc.constantFrom(...PROTECTED), (p, cmd) => {
      expect(bash(cmd, withPolicy(p)).verdict).toBe("deny");
    }), { numRuns: 150 });
  });

  it("I3: unanalyzable ⇒ never allow or warn", () => {
    fc.assert(fc.property(arbPolicy, fc.constantFrom(...UNANALYZABLE), (p, cmd) => {
      expect(["ask", "deny"]).toContain(bash(cmd, withPolicy(p)).verdict);
    }), { numRuns: 150 });
  });

  it("I13: autopilot never returns ask", () => {
    const cmds = ["git push --force", "rm x", "eval x", "curl x", "ls", "npm publish", "terraform apply"];
    fc.assert(fc.property(arbPolicy, fc.constantFrom(...cmds), (p, cmd) => {
      const d = bash(cmd, withPolicy({ ...p, mode: "autopilot" }));
      expect(d.verdict).not.toBe("ask");
      if (d.verdictBeforeMode !== undefined) expect(d.verdictBeforeMode).toBe("ask");
    }), { numRuns: 200 });
  });

  it("I15: remembered rules never lift a floor or a ≥ high finding", () => {
    for (const mode of MODES) {
      const c = withPolicy({ mode });
      expect(bash("git push --force", c).verdict).not.toBe("deny"); // sanity: remembered may relax the mode-driven ask
      for (const cmd of [...CRITICAL, ...PROTECTED]) expect(bash(cmd, c).verdict, `${mode} ${cmd}`).toBe("deny");
      for (const cmd of UNANALYZABLE) expect(["ask", "deny"], `${mode} ${cmd}`).toContain(bash(cmd, c).verdict);
    }
  });

  it("disabling a non-suppressible rule has no effect", () => {
    const c = ctx({ policy: { mode: "balanced", disabledRules: ["CP-SELF-001", "CP-SHELL-001", "CP-ACTION-001"] } });
    expect(ruleIds(bash("rm -rf /", c))).toContain("CP-ACTION-001");
    expect(ruleIds(bash("eval x", c))).toContain("CP-SHELL-001");
    expect(bash("echo x > ~/.claude/settings.json", c).verdict).toBe("deny");
  });

  it("disabling a suppressible rule removes it and reports the suppression", () => {
    const c = ctx({ policy: { mode: "balanced", disabledRules: ["CP-EXFIL-040"] } });
    const d = builtin("Read", { file_path: "/home/u/proj/.env" }, c);
    expect(ruleIds(d)).not.toContain("CP-EXFIL-040");
    expect(d.suppressed).toEqual([{ ruleId: "CP-EXFIL-040", count: 1 }]);
  });
});

describe("mode table (§6.2)", () => {
  it("tagOverrides apply to R3 only and the most restrictive tag wins (§6.3)", () => {
    const c = ctx({ policy: { mode: "balanced", tagOverrides: { "vcs.push": "allow" } } });
    expect(bash("git push --force", c).verdict).toBe("ask");
    expect(bash("git push origin main", c).verdict).toBe("allow");
    const deny = ctx({ policy: { mode: "autopilot", tagOverrides: { "net.egress": "deny" } } });
    expect(bash("curl https://example.com", deny).verdict).toBe("deny");
  });

  it("remembered rule turns a mode-driven ask into allow, scoped to server+tool+tag", () => {
    const remembered = [{ projectIdHash: "p", serverId: "builtin", toolName: "Bash", actionTag: "publish.public" as const, createdAt: "2026-01-01T00:00:00Z" }];
    expect(bash("npm publish", ctx({ remembered })).verdict).toBe("allow");
    expect(bash("git reset --hard", ctx({ remembered })).verdict).toBe("ask");
  });

  it("strict asks on medium findings; balanced warns", () => {
    const read = (mode: ApprovalMode) => builtin("Read", { file_path: "/home/u/.aws/credentials" }, ctx({ policy: { mode } })).verdict;
    expect(read("strict")).toBe("ask");
    expect(read("balanced")).toBe("warn");
    expect(read("autopilot")).toBe("warn");
  });

  it("Decision records the mode", () => {
    for (const mode of MODES) expect(bash("ls", ctx({ policy: { mode } })).mode).toBe(mode);
  });

  it("verdictBeforeMode is set when autopilot turns ask into deny", () => {
    const d = bash("git push --force", ctx({ policy: { mode: "autopilot" } }));
    expect(d.verdict).toBe("deny");
    expect(d.verdictBeforeMode).toBe("ask");
  });
});

describe("I4 / R10–R12: degraded and internal errors", () => {
  it("a command over maxCommandBytes is unanalyzable (never allow)", () => {
    const d = bash("echo " + "a".repeat(20_000));
    expect(d.actionRisk.unanalyzable).toBe(true);
    expect(["ask", "deny"]).toContain(d.verdict);
  });

  it("input over maxInputBytes: degraded; high-risk-by-default ⇒ deny", () => {
    const d = checkToolCall("{" + " ".repeat(2_000_000) + "}", ctx());
    expect(d.degraded).toBe(true);
    expect(d.verdict).toBe("deny");
  });

  it("a garbage input never allows", () => {
    for (const input of [null, 42, "not json", [], { toolName: 5 }]) {
      const d = checkToolCall(input, ctx());
      expect(d.verdict, JSON.stringify(input)).toBe("deny");
    }
  });

  it("a broken SessionContext never allows", () => {
    const d = checkToolCall({ serverId: "builtin", toolName: "Bash", arguments: { command: "ls" } }, {} as SessionContext);
    expect(d.verdict).toBe("deny");
  });
});
