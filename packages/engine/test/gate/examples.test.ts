// The three reference verdicts requested at the Step 4 pause, across all modes.
import { describe, expect, it } from "vitest";
import { acrossModes, bash, builtin, ctx, ruleIds } from "../helpers.js";

const COMMIT_HEREDOC = `git commit -m "$(cat <<'EOF'
Fix flaky retry in uploader

Co-Authored-By: Someone <someone@example.com>
EOF
)"`;

describe("reference verdicts", () => {
  it("git push --force: ask in strict and balanced, deny in autopilot", () => {
    expect(acrossModes((c) => bash("git push --force origin main", c))).toEqual(["ask", "ask", "deny"]);
    const d = bash("git push --force origin main");
    expect(d.actionRisk.level).toBe("high-risk");
    expect(d.actionRisk.tags).toContain("vcs.force-push");
    expect(d.actionRisk.unanalyzable).toBe(false);
  });

  it("git commit with $(cat <<'EOF' … EOF): allow in every mode", () => {
    expect(acrossModes((c) => bash(COMMIT_HEREDOC, c))).toEqual(["allow", "allow", "allow"]);
    const d = bash(COMMIT_HEREDOC);
    expect(d.actionRisk.level).toBe("write-reversible");
    expect(d.actionRisk.tags).toContain("vcs.commit");
    expect(d.actionRisk.unanalyzable).toBe(false);
  });

  it("Edit of ~/.claude/settings.json: deny in every mode (self-protection)", () => {
    const run = (c = ctx()) =>
      builtin("Edit", { file_path: "/home/u/.claude/settings.json", old_string: "a", new_string: "b" }, c);
    expect(acrossModes(run)).toEqual(["deny", "deny", "deny"]);
    const d = run();
    expect(d.actionRisk.selfProtection).toBe(true);
    expect(ruleIds(d)).toContain("CP-SELF-001");
  });
});
