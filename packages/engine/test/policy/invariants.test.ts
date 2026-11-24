// Policy invariants: I1–I4, I13, I15, I17 and the user-policy limits.
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
  // A hostile "remembered" rule and session grant for every tag on Bash, in this project and session.
  projectIdHash: "p",
  remembered: ALL_TAGS.map((actionTag) => ({ projectIdHash: "p", serverId: "builtin", toolName: "Bash", actionTag, createdAt: "2026-01-01T00:00:00Z" })),
  sessionGrants: ALL_TAGS.map((actionTag) => ({ sessionId: base.sessionId, serverId: "builtin", toolName: "Bash", actionTag, createdAt: "2026-01-01T00:00:00Z" })),
});

/** The hard floor (force push, history rewrite, wipes, payments, prod deploys, publishing): nothing the user set up lowers it. */
const HARD_FLOOR = ["git push --force", "git push origin +main", "git filter-branch --force HEAD", "npm publish", "vercel --prod", "gh release create v1"];
/** Other irreversible actions: ask by default in every mode, but a remembered rule or grant may lift them. */
const LIFTABLE_IRREVERSIBLE = ["git reset --hard", "terraform apply", "gh pr create -t x -b y", "chmod -R 777 .", "claude -p hi", "git config core.hooksPath .h"];

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

  it("I15: remembered rules and session grants never lift a floor or a ≥ high finding", () => {
    for (const mode of MODES) {
      const c = withPolicy({ mode });
      // Sanity: the hostile rules are live. In strict, a reversible high-risk call is lifted to allow.
      if (mode === "strict") expect(bash("curl https://example.com", c).verdict).toBe("allow");
      for (const cmd of HARD_FLOOR) expect(bash(cmd, c).verdict, `${mode} ${cmd}`).toBe(mode === "autopilot" ? "deny" : "ask");
      // Lifted only because the hostile context remembers every tag; without it they ask (next test).
      for (const cmd of LIFTABLE_IRREVERSIBLE) expect(["allow", "warn"], `${mode} ${cmd}`).toContain(bash(cmd, c).verdict);
      for (const cmd of [...CRITICAL, ...PROTECTED]) expect(bash(cmd, c).verdict, `${mode} ${cmd}`).toBe("deny");
      for (const cmd of UNANALYZABLE) expect(["ask", "deny"], `${mode} ${cmd}`).toContain(bash(cmd, c).verdict);
    }
  });

  it("liftable irreversible actions still ask by default in every mode (deny in autopilot)", () => {
    for (const cmd of LIFTABLE_IRREVERSIBLE) {
      expect(MODES.map((mode) => bash(cmd, ctx({ policy: { mode } })).verdict), cmd).toEqual(["ask", "ask", "deny"]);
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

describe("mode table", () => {
  it("tagOverrides apply to R3 only and the most restrictive tag wins", () => {
    // A plain push carries net.egress too (network-touching is high-risk), so both tags are overridden.
    const c = ctx({ policy: { mode: "balanced", tagOverrides: { "vcs.push": "allow", "net.egress": "allow" } } });
    expect(bash("git push --force", c).verdict).toBe("ask");
    expect(bash("git push origin main", c).verdict).toBe("allow");
    const deny = ctx({ policy: { mode: "autopilot", tagOverrides: { "net.egress": "deny" } } });
    expect(bash("curl https://example.com", deny).verdict).toBe("deny");
  });

  it("remembered rule turns a mode-driven ask into allow, scoped to project+server+tool+tag", () => {
    const remembered = [{ projectIdHash: "p", serverId: "builtin", toolName: "Bash", actionTag: "net.egress" as const, createdAt: "2026-01-01T00:00:00Z" }];
    const strict = { mode: "strict" as const };
    expect(bash("curl https://example.com", ctx({ policy: strict, projectIdHash: "p", remembered })).verdict).toBe("allow");
    expect(bash("curl https://example.com", ctx({ policy: strict, projectIdHash: "other", remembered })).verdict).toBe("ask");
    expect(bash("curl https://example.com", ctx({ policy: strict, remembered })).verdict).toBe("ask"); // no project given
    expect(builtin("WebFetch", { url: "https://example.com" }, ctx({ policy: strict, projectIdHash: "p", remembered })).verdict).toBe("ask"); // other tool
    expect(bash("rm build.log", ctx({ policy: strict, projectIdHash: "p", remembered })).verdict).toBe("ask"); // other tag
  });

  it("strict asks on medium findings; balanced warns", () => {
    const read = (mode: ApprovalMode) => builtin("Read", { file_path: "/home/u/.aws/credentials" }, ctx({ policy: { mode } })).verdict;
    expect(read("strict")).toBe("ask");
    expect(read("balanced")).toBe("warn");
    expect(read("autopilot")).toBe("warn");
  });

  it("rev 5: irreversible or public actions ask in every mode (deny in autopilot)", () => {
    const cmds = ["git push --force", "git reset --hard", "npm publish", "vercel --prod", "terraform apply", "chmod -R 777 .", "claude -p hi", "gh pr create -t x -b y"];
    for (const cmd of cmds) {
      expect(MODES.map((mode) => bash(cmd, ctx({ policy: { mode } })).verdict), cmd).toEqual(["ask", "ask", "deny"]);
      expect(bash(cmd, ctx({ policy: { mode: "autopilot" } })).verdictBeforeMode, cmd).toBe("ask");
    }
    // Reversible high-risk actions keep the old behaviour: warn in balanced and autopilot.
    for (const cmd of ["rm build.log", "curl https://example.com", "git push origin main"]) {
      expect(MODES.map((mode) => bash(cmd, ctx({ policy: { mode } })).verdict), cmd).toEqual(["ask", "warn", "warn"]);
    }
  });

  it("irreversible or public actions are a floor: no tag override, remembered rule or session grant lowers them", () => {
    const lift = (mode: ApprovalMode) => ctx({
      policy: { mode, tagOverrides: { "publish.public": "allow", "vcs.force-push": "allow", "vcs.push": "allow", "net.egress": "allow", "fs.destroy": "allow" } },
      projectIdHash: "p",
      remembered: [{ projectIdHash: "p", serverId: "builtin", toolName: "Bash", actionTag: "publish.public", createdAt: "2026-01-01T00:00:00Z" }],
      sessionGrants: [{ sessionId: "s1", serverId: "builtin", toolName: "Bash", actionTag: "vcs.force-push", createdAt: "2026-01-01T00:00:00Z" }],
    });
    for (const cmd of ["npm publish", "git push --force"]) {
      expect(MODES.map((m) => bash(cmd, lift(m)).verdict), cmd).toEqual(["ask", "ask", "deny"]);
    }
    // A tag override may still raise the floor to deny.
    expect(bash("npm publish", ctx({ policy: { mode: "balanced", tagOverrides: { "publish.public": "deny" } } })).verdict).toBe("deny");
    expect(bash("rm -rf /", lift("balanced")).verdict).toBe("deny");
  });

  it("Decision records the mode", () => {
    for (const mode of MODES) expect(bash("ls", ctx({ policy: { mode } })).mode).toBe(mode);
  });

  it("verdictBeforeMode is set when autopilot turns ask into deny", () => {
    // An unanalyzable command asks (R9 floor); autopilot turns that ask into deny (R15).
    const d = bash("eval \"$X\"", ctx({ policy: { mode: "autopilot" } }));
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
