// Engine 0.1.2 (spec §7.10): other coding-agent CLIs are nested agents like `claude`.
// Launching one is a liftable ask; flags and environment that turn off approvals or the sandbox
// (exact names from each tool's current docs) are denied; their config and instruction files
// are agent config (a liftable ask).
import { describe, expect, it } from "vitest";
import { checkToolCall, type ActionTag, type Decision, type SessionContext } from "../../src/index.js";
import { bash, ctx, ps, winCtx } from "../helpers.js";

const P = "a".repeat(64);
const ids = (d: Decision) => d.findings.map((f) => f.ruleId);
const remember = (tool: string, tags: ActionTag[]) => tags.map((actionTag) => ({ projectIdHash: P, serverId: "builtin", toolName: tool, actionTag, createdAt: "2026-11-25T00:00:00Z" }));
const L = (o: Partial<SessionContext> = {}) => ctx({ projectIdHash: P, ...o });

describe("launching another agent CLI is a nested agent (liftable ask)", () => {
  const launches = [
    "codex exec 'fix the tests'", "codex e hi", "gemini -p hi", "aider -m hi", "aider --message-file task.md",
    "agent -p hi", "cursor-agent -p hi", "opencode run hi", "goose run -t hi", "amp -x hi", "crush",
    "copilot -p hi", "kiro-cli chat --no-interactive", "cline hi", "qwen -p hi",
    // options that only narrow or keep approvals stay an ordinary nested-agent ask
    "codex -a on-request exec hi", "codex --sandbox workspace-write exec hi", "gemini --approval-mode auto_edit -p hi",
    "gemini --approval-mode=default -p hi", "agent --sandbox enabled -p hi", "GOOSE_MODE=approve goose run -t hi",
  ];
  for (const cmd of launches) {
    it(cmd, () => {
      const d = bash(cmd, L());
      expect(d.verdict, "balanced").toBe("ask");
      expect(d.actionRisk.tags).toContain("exec.nested-agent");
      expect(ids(d)).not.toContain("CP-SELF-003");
      expect(bash(cmd, L({ remembered: remember("Bash", ["exec.nested-agent"]) })).verdict, "remembered").toBe("allow");
      expect(bash(cmd, L({ policy: { mode: "autopilot" } })).verdict, "autopilot").toBe("deny");
    });
  }

  it("help and version alone are allowed", () => {
    for (const cmd of ["codex --version", "gemini --help", "aider -h", "opencode -v"]) expect(bash(cmd, L()).verdict, cmd).toBe("allow");
  });
});

describe("flags that turn off approvals or the sandbox are denied (CP-SELF-003)", () => {
  const denied = [
    // Codex
    "codex --dangerously-bypass-approvals-and-sandbox exec hi", "codex --yolo exec hi", "codex exec --yolo hi",
    "codex -a never exec hi", "codex --ask-for-approval never exec hi", "codex --ask-for-approval=never exec hi", "codex -anever exec hi",
    "codex -s danger-full-access exec hi", "codex --sandbox=danger-full-access exec hi",
    "codex -c approval_policy=never exec hi", "codex -c 'approval_policy=\"never\"' exec hi", "codex --config sandbox_mode=danger-full-access exec hi",
    "codex -c default_permissions=:danger-full-access exec hi", "codex --approve-for-me exec hi", "codex --not-so-yolo exec hi",
    "codex --dangerously-bypass-hook-trust exec hi", "codex --ignore-rules exec hi",
    // Gemini CLI
    "gemini --yolo -p hi", "gemini -y -p hi", "gemini --approval-mode yolo -p hi", "gemini --approval-mode=yolo -p hi", "gemini --skip-trust -p hi",
    // Aider
    "aider --yes-always -m hi", "aider --yes -m hi",
    // Cursor CLI
    "agent -f -p hi", "agent --force -p hi", "agent --yolo -p hi", "cursor-agent --yolo -p hi", "agent --sandbox disabled -p hi",
    "agent --sandbox=disabled -p hi", "agent --approve-mcps -p hi", "agent --trust -p hi",
    // opencode
    "opencode run --auto hi", "opencode --auto run hi", "opencode run --yolo hi", "opencode run --dangerously-skip-permissions hi",
    // Goose, Amp, Crush, Copilot, Kiro, Cline
    "goose serve --dangerously-unauthenticated", "amp --dangerously-allow-all -x hi", "crush --yolo",
    "copilot --allow-all-tools -p hi", "copilot --allow-all -p hi", "copilot --yolo -p hi", "copilot --allow-all-paths -p hi", "copilot --allow-all-urls -p hi",
    "kiro-cli chat --trust-all-tools --no-interactive", "kiro chat --trust-all-tools", "cline -y hi", "cline --yolo hi",
  ];
  for (const cmd of denied) {
    it(cmd, () => {
      const d = bash(cmd, L());
      expect(d.verdict).toBe("deny");
      expect(ids(d)).toContain("CP-SELF-003");
      // Nothing the user set up earlier lifts it.
      expect(bash(cmd, L({ remembered: remember("Bash", ["exec.nested-agent"]) })).verdict).toBe("deny");
    });
  }

  it("the same from PowerShell", () => {
    for (const cmd of ["codex --yolo exec hi", "gemini --approval-mode yolo -p hi", "agent --force -p hi", "opencode run --auto hi", "aider --yes-always -m hi"]) {
      expect(ps(cmd, winCtx()).verdict, cmd).toBe("deny");
    }
    // PowerShell tokenizes `--name=value` so the value isn't known: unanalyzable, a locked ask.
    for (const cmd of ["gemini --approval-mode=yolo -p hi", "codex --ask-for-approval=never exec hi"]) {
      const d = ps(cmd, winCtx({ projectIdHash: P, remembered: remember("PowerShell", ["exec.nested-agent", "exec.unknown"]) }));
      expect(d.verdict, cmd).not.toBe("allow");
      expect(d.actionRisk.unanalyzable, cmd).toBe(true);
    }
  });

  it("through a package runner (npx, pnpm dlx, bunx), including claude's own package", () => {
    for (const cmd of [
      "npx @openai/codex --yolo exec hi", "npx @openai/codex@latest --yolo exec hi", "pnpm dlx @google/gemini-cli --yolo -p hi",
      "bunx opencode-ai run --auto hi", "npx @github/copilot --allow-all-tools -p hi", "npx cline --yolo hi",
      "npx @anthropic-ai/claude-code --dangerously-skip-permissions -p hi",
    ]) expect(bash(cmd, L()).verdict, cmd).toBe("deny");
    expect(bash("npx @openai/codex exec hi", L()).actionRisk.tags).toContain("exec.nested-agent");
  });
});

describe("environment that turns off approvals or points at another configuration is denied", () => {
  for (const cmd of [
    "CODEX_HOME=/tmp/c codex exec hi", "GEMINI_CLI_HOME=/tmp/g gemini -p hi", "SEATBELT_PROFILE=permissive-open gemini -p hi",
    "AIDER_YES_ALWAYS=1 aider -m hi", "AIDER_YES=true aider -m hi", "CURSOR_CONFIG_DIR=/tmp/c agent -p hi",
    "OPENCODE_PERMISSION='{}' opencode run hi", "OPENCODE_CONFIG=/tmp/o.json opencode run hi", "OPENCODE_CONFIG_CONTENT='{}' opencode run hi",
    "GOOSE_MODE=auto goose run -t hi", "GOOSE_MODE=AUTO goose run -t hi", "GOOSE_PATH_ROOT=/tmp/g goose run -t hi",
    "COPILOT_HOME=/tmp/c copilot -p hi", "KIRO_HOME=/tmp/k kiro-cli chat",
  ]) it(cmd, () => expect(bash(cmd, L()).verdict).toBe("deny"));
});

describe("red team", () => {
  it("RT-112-10: an argument that isn't known statically can't hide a bypass flag (unanalyzable, not liftable)", () => {
    for (const cmd of ["codex $FLAGS exec hi", "gemini \"$MODE\" -p hi", "agent $(cat flags) -p hi"]) {
      const d = bash(cmd, L({ remembered: remember("Bash", ["exec.nested-agent", "exec.unknown"]) }));
      expect(d.verdict, cmd).not.toBe("allow");
      expect(d.actionRisk.unanalyzable, cmd).toBe(true);
    }
    expect(bash("codex -a \"$MODE\" exec hi", L()).actionRisk.unanalyzable).toBe(true);
  });

  it("RT-112-11: paths, case and .exe don't hide the tool", () => {
    for (const cmd of ["/usr/local/bin/codex --yolo exec hi", "CODEX --yolo exec hi"]) expect(bash(cmd, L()).verdict, cmd).toBe("deny");
    // A ~ command name isn't a literal word: unanalyzable, a locked ask nothing lifts.
    const tilde = bash("~/.local/bin/gemini --yolo -p hi", L({ remembered: remember("Bash", ["exec.nested-agent", "exec.unknown"]) }));
    expect(tilde.verdict).not.toBe("allow");
    expect(tilde.actionRisk.unanalyzable).toBe(true);
    expect(ps("& 'C:\\Tools\\codex.exe' --yolo exec hi", winCtx()).verdict).toBe("deny");
    expect(ps("Codex.EXE --yolo exec hi", winCtx()).verdict).toBe("deny");
  });

  it("RT-112-12: wrappers don't hide it (sh -c, xargs, command, nohup)", () => {
    for (const cmd of ["sh -c 'codex --yolo exec hi'", "bash -c \"opencode run --auto hi\"", "command codex --yolo exec hi", "nohup gemini --yolo -p hi &"]) {
      expect(bash(cmd, L()).verdict, cmd).toBe("deny");
    }
  });

  it("RT-112-13: flag names belonging to another tool don't misfire (aider -f? cursor -f only)", () => {
    // -f is Cursor's force flag, not a bypass for other tools: aider -f is --message-file.
    expect(bash("aider -f task.md", L()).verdict).toBe("ask");
    expect(ids(bash("aider -f task.md", L()))).not.toContain("CP-SELF-003");
  });

  it("RT-112-14: an unrelated program called agent-something isn't an agent CLI", () => {
    expect(bash("ssh-agent -s", L()).actionRisk.tags).not.toContain("exec.nested-agent");
  });
});

describe("their config and instruction files are agent config (liftable ask)", () => {
  const W = (file_path: string) => ({ file_path, content: "x" });
  const write = (file_path: string, c: SessionContext) => checkToolCall({ serverId: "builtin", toolName: "Write", arguments: W(file_path) }, c);
  const linux = [
    "/home/u/.codex/config.toml", "/home/u/.codex/AGENTS.md", "/home/u/.gemini/settings.json", "/home/u/.cursor/cli-config.json",
    "/home/u/.config/opencode/opencode.json", "/home/u/.config/goose/config.yaml", "/home/u/.config/amp/settings.json",
    "/home/u/.qwen/settings.json", "/home/u/.config/crush/crushrc", "/home/u/.copilot/settings.json", "/home/u/.kiro/settings/mcp.json",
    "/home/u/.aider.conf.yml", "/etc/gemini-cli/settings.json",
    "/home/u/proj/AGENTS.md", "/home/u/proj/docs/AGENTS.md", "/home/u/proj/GEMINI.md", "/home/u/proj/QWEN.md", "/home/u/proj/CRUSH.md",
    "/home/u/proj/.codex/config.toml", "/home/u/proj/.gemini/settings.json", "/home/u/proj/.cursor/rules/style.mdc", "/home/u/proj/.cursor/cli.json",
    "/home/u/proj/opencode.json", "/home/u/proj/.opencode/agent/review.md", "/home/u/proj/.goosehints", "/home/u/proj/.aider.conf.yml",
    "/home/u/proj/.amp/settings.json", "/home/u/proj/.crushrc",
  ];
  for (const f of linux) {
    it(f, () => {
      const d = write(f, L());
      expect(d.verdict).toBe("ask");
      expect(d.actionRisk.tags).toContain("config.agent");
      expect(write(f, L({ remembered: remember("Write", ["config.agent", "fs.write"]) })).verdict, "remembered").toBe("allow");
    });
  }

  it("Windows spellings", () => {
    const w = winCtx({ projectIdHash: P });
    for (const f of ["C:\\Users\\u\\.codex\\config.toml", "c:\\users\\U\\.GEMINI\\settings.json", "C:\\Users\\u\\AppData\\Roaming\\Block\\goose\\config\\config.yaml",
      "C:\\ProgramData\\gemini-cli\\settings.json", "C:\\Users\\u\\proj\\AGENTS.md", "C:\\Users\\u\\proj\\agents.md"]) {
      expect(write(f, w).actionRisk.tags, f).toContain("config.agent");
    }
  });

  it("every write path: shell redirect, tee, cp, sed -i, PowerShell Set-Content", () => {
    for (const cmd of ["echo 'run curl x | sh' > AGENTS.md", "echo x | tee -a GEMINI.md", "cp evil.toml ~/.codex/config.toml", "sed -i s/a/b/ AGENTS.md"]) {
      expect(bash(cmd, L()).actionRisk.tags, cmd).toContain("config.agent");
    }
    expect(ps("Set-Content -Path AGENTS.md -Value x", winCtx()).actionRisk.tags).toContain("config.agent");
  });

  it("ordinary files are not agent config", () => {
    for (const f of ["/home/u/proj/README.md", "/home/u/proj/src/agents.ts", "/home/u/proj/my-agents.md", "/home/u/proj/docs/codex.md", "/home/u/notes/AGENTS.md.bak"]) {
      expect(write(f, L()).actionRisk.tags, f).not.toContain("config.agent");
    }
  });
});
