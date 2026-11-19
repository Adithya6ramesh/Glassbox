// Shared test helpers. Tests import the engine from source.
import {
  EMBEDDED_BASELINE,
  checkToolCall,
  type ApprovalMode,
  type Decision,
  type SessionContext,
  type SessionSignal,
  type ToolCallInput,
  type UserPolicy,
} from "../src/index.js";

export const HOME = "/home/u";
export const PROJECT = "/home/u/proj";

export function ctx(overrides: Partial<SessionContext> = {}): SessionContext {
  return {
    sessionId: "s1",
    platform: "linux",
    homeDir: HOME,
    cwd: PROJECT,
    caseInsensitiveFs: false,
    glassboxDirs: [`${HOME}/.glassbox`],
    servers: [],
    policy: { mode: "balanced" },
    ruleset: EMBEDDED_BASELINE,
    // The wall-clock backstop (hardStopMs, default 100) makes a verdict depend on machine
    // speed: a cold first call on a busy CI runner once crossed it and turned an `allow`
    // into a `warn` (the Step 5/6 flake). Classification tests use a generous limit; the
    // backstop itself is tested with explicit limits in test/gate/hard-stop.test.ts.
    limits: { hardStopMs: 60_000 },
    ...overrides,
  };
}

export function winCtx(overrides: Partial<SessionContext> = {}): SessionContext {
  return ctx({
    platform: "win32",
    homeDir: "C:\\Users\\u",
    cwd: "C:\\Users\\u\\proj",
    caseInsensitiveFs: true,
    glassboxDirs: ["C:\\Users\\u\\.glassbox"],
    ...overrides,
  });
}

export const MODES: readonly ApprovalMode[] = ["strict", "balanced", "autopilot"];

export function policy(mode: ApprovalMode, extra: Partial<UserPolicy> = {}): UserPolicy {
  return { mode, ...extra };
}

export function bash(command: string, c: SessionContext = ctx()): Decision {
  return checkToolCall({ serverId: "builtin", toolName: "Bash", arguments: { command } }, c);
}

export function ps(command: string, c: SessionContext = winCtx()): Decision {
  return checkToolCall({ serverId: "builtin", toolName: "PowerShell", arguments: { command } }, c);
}

export function builtin(toolName: string, args: unknown, c: SessionContext = ctx()): Decision {
  return checkToolCall({ serverId: "builtin", toolName, arguments: args }, c);
}

export function call(input: ToolCallInput, c: SessionContext = ctx()): Decision {
  return checkToolCall(input, c);
}

export function ruleIds(d: { findings: readonly { ruleId: string }[] }): string[] {
  return d.findings.map((f) => f.ruleId);
}

export function withSignals(signals: readonly SessionSignal[], c: SessionContext = ctx()): SessionContext {
  return { ...c, signals };
}

/** Every verdict across the three modes, in MODES order. */
export function acrossModes(run: (c: SessionContext) => Decision, base: SessionContext = ctx()) {
  return MODES.map((mode) => run({ ...base, policy: { ...base.policy, mode } }).verdict);
}

// Realistic-looking but fake secrets. Built from pieces so this file itself
// doesn't trip secret scanners.
export const FAKE = {
  github: "ghp_" + "R4nd0mT0k3nV4lu3xYz9" + "8765432101234567",
  aws: "AKIA" + "Q3ZRT7Y2X4WPLM5N",
  slack: "xoxb-" + "123456789012-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx",
  stripe: "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "Zq",
  anthropic: "sk-ant-api03-" + "x".repeat(20) + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7" + "b".repeat(40) + "-AA",
  pem: "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH " + "PRIVATE KEY-----",
  pg: "postgres://app:" + "s3cr3tPassw0rd" + "@db.internal:5432/prod",
} as const;
