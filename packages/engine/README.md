# @glassbox-ai/engine

[![npm version](https://img.shields.io/npm/v/@glassbox-ai/engine.svg)](https://www.npmjs.com/package/@glassbox-ai/engine)

Checks what an AI agent is about to do and what it reads. For each step it answers allow,
warn, ask or deny. It also grades MCP servers from their metadata. It's a library with no I/O;
it is deterministic and never throws.

**Status: early, v0.1.** The API and the rules will change.

```sh
npm install @glassbox-ai/engine
```

```js
import { EMBEDDED_BASELINE, checkToolCall } from "@glassbox-ai/engine";

const decision = checkToolCall(
  { serverId: "builtin", toolName: "Bash", arguments: { command: "rm -rf ~/Documents" } },
  {
    sessionId: "s1", platform: "linux", homeDir: "/home/me", cwd: "/home/me/project",
    caseInsensitiveFs: false, glassboxDirs: ["/home/me/.glassbox"], servers: [],
    policy: { mode: "balanced" }, ruleset: EMBEDDED_BASELINE,
  },
);
decision.verdict; // "deny"
```

The full guide covers `checkToolResult`, `analyzeServer`, session signals and modes. The
benchmark results include their limits: on a sealed holdout, 50.9% of attacks were stopped
overall, 92.3% of tool poisoning but only 25.3% of prompt injection in tool results, and 2.1%
of benign cases were stopped. See https://github.com/Adithya6ramesh/Glassbox#readme

Apache-2.0.
