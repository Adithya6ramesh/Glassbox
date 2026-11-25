# Changelog: @glassbox-ai/engine

## 0.1.2 (unreleased)

**Uploads on Windows**
- **Uploading a file from inside the project no longer asks on Windows.** The project folder was
  compared in its raw form (backslashes) with the normalized file path, so every Windows upload
  counted as "from outside the project" (`CP-EXFIL-035`, ask). The project folder is now
  normalized the same way (drive-letter case and `/` vs `\` no longer matter).
- These still count as outside the project and ask: UNC paths (also `\\localhost\C$\…`), the
  `\\?\` and `\\.\` prefixes, drive-relative paths (`C:notes.txt`), 8.3 short names that don't
  match the project's own spelling, `..` out of the project, and sibling folders whose name starts
  with the project's (`C:\proj-evil` next to `C:\proj`).
- A caller-resolved real path (`resolvedPaths`) now counts for uploads on every platform: a file
  inside the project reached through a junction or symlink that leads outside it asks, and one
  that leads to a sensitive file asks as sensitive (`CP-EXFIL-030`).

**Persistence outside the project**
- **"Allow & remember" can no longer silence persistence outside the project.** A remembered rule
  never lifts the ask for startup files and profiles (`CP-SELF-005`: `~/.bashrc`, `~/.zshrc`,
  `~/.profile`…, PowerShell profiles) or scheduled jobs and autostart (`CP-SELF-006`: scheduled
  tasks, the Startup folder, LaunchAgents/LaunchDaemons, systemd user units, XDG autostart,
  cron). A session grant covering the call (every one of its liftable tags) may lift them. In
  0.1.1 neither could. New export `GRANT_LIFTABLE_FINDINGS`.
- Any other high finding in the same call still asks; unanalyzable calls, edits to files an
  approved job runs (`CP-SELF-007`), remote-access persistence (`CP-SELF-004`) and Claude Code
  policy keys are unchanged.
- **Windows Run keys are persistence.** Writes to `…\CurrentVersion\Run`, `RunOnce`, `RunOnceEx`,
  `RunServices[Once]` (HKCU, HKLM, WOW6432Node) and the Explorer policy Run key, through
  PowerShell registry cmdlets or `reg add`/`reg delete`, are now a login autostart job
  (`CP-SELF-006`). In 0.1.1 they were an ordinary registry write a remembered rule could lift.
- Persistence inside the project (`.husky`, `.git/hooks`, `.envrc`, `.pre-commit-config.yaml`)
  stays liftable by remembered rules and session grants, as before.

## 0.1.1 (2026-11-25)

Stricter defaults. Some calls that 0.1.0 allowed now ask or deny.

**Built-in tools**
- New export `BUILTIN_TOOLS`: every built-in Claude Code tool from the current tools reference
  (2.1.331), by category: `read`, `write`, `command`, `network`, `agent`, `other`.
- `Monitor` runs shell commands, so its `command` gets the same analysis as `Bash`. A WebSocket
  watch (`ws.url`) is network egress and records the host only.
- **A built-in tool the engine doesn't know is now unanalyzable** (ask in strict and balanced,
  deny in autopilot). In 0.1.0 it was allowed.
- `Artifact` and `ShareOnboardingGuide` send content off the machine: high-risk `net.egress`.
  `RemoteTrigger` starts agents in the cloud: `exec.nested-agent`, which asks.

**Policy**
- **Hard floor.** Force push, history rewrite, wipes, payments, production deploys and publishing
  (new export `HARD_FLOOR_TAGS`) ask in strict and balanced and deny in autopilot, whatever the
  user set up and whatever the ruleset says: a `tagOverrides` entry can only raise them to deny,
  and remembered rules and session grants never lift them.
- The other irreversible-or-public actions (discarding changes, schema or unscoped database
  writes, infrastructure changes, sending messages, permission changes, files that run commands
  later, nested agents) still ask in every mode by default, but stay liftable as in 0.1.0.
- `gh pr …` and `gh issue …` writes are now `message.send` instead of `publish.public`: they
  still ask by default, and can be remembered. Releases, gists, repository changes and
  `gh api` writes stay `publish.public` (hard floor).
- **Remembered rules are scoped to a project.** New `SessionContext.projectIdHash`; a remembered
  rule applies only when its `projectIdHash` equals it. Without a `projectIdHash`, no remembered
  rule applies.
- **Session grants.** New `SessionContext.sessionGrants` (`SessionGrant`): permissions the user
  granted for one session. They apply only when their `sessionId` equals the context's, and,
  like remembered rules, lift mode-driven asks only.
- Remembered rules and grants count only with their own string properties (inherited fields
  don't), and at most 1,000 of each are read.

**Self-protection**
- The Glassbox CLI's protection-changing subcommands (`mode`, `allow`, `uninstall`, …) are now
  caught however the CLI is launched: package runners (`npx`, `bunx`, `pnpx`, `pnpm dlx/exec`,
  `npm exec`, `yarn dlx`) and interpreters running the CLI script directly. In 0.1.0,
  `npx glassbox allow …` was allowed. New subcommand names `deny`, `forget` and `revoke` are
  covered in advance.

**Signed rulesets**
- The first production signing key is embedded: `gbx-2026-a` (Ed25519; SHA-256 of the raw public
  key `67872a7d…799f62a0`). Rulesets signed with it are accepted; anything else still falls back
  to the embedded baseline. The private key is held offline by the maintainer.
- Verification uses a private copy of the key list, so changing the bytes of the exported
  `EMBEDDED_TRUSTED_KEYS` doesn't change which keys are trusted.

**Other**
- Source comments no longer refer to internal design documents.
- Releases are staged on npm by a GitHub Actions workflow and need the maintainer's 2FA
  approval; they carry npm provenance. 0.1.0 was published from a local machine without it.
