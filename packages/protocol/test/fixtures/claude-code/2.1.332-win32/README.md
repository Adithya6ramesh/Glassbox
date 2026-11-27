# Claude Code hook fixtures (2.1.332, Windows)

Real hook payloads, captured from Claude Code 2.1.332 on Windows 11 in `-p` mode, in a
throwaway folder outside any repository. Each session ran with `--permission-mode default`
(one with `acceptEdits`), a short `--allowedTools` list and `--no-session-persistence`, and
loaded a one-session test plugin with `--plugin-dir`. No session used bypass mode.

## `input/`: what Claude Code sends to a hook

A capture hook wrote each event's stdin to a file and exited 0 without output.

| Run | What it exercised |
|---|---|
| run1 | Write, Read, Edit, Glob, Grep, Bash (one success, one non-zero exit), a background subagent |
| run2 | Commands that Claude Code auto-approves as read-only: `whoami` (Bash), `Get-Date` (PowerShell), `echo tick` (Monitor) |
| run3 | Commands Claude Code refuses in `-p` mode: Bash `mkdir`, Write |

## `output/`: what a hook's reply does

A test hook denied only the exact command `echo glassbox-deny-test`, asked only for
`echo glassbox-ask-test`, and returned no decision for everything else. Each file holds
the scenario, the hook's stdin, its reply, and what was observed: whether the tool ran
(a PostToolUse with the same `tool_use_id`) and the exact text Claude received (from
PostToolBatch).

| Run | Reply | Hook shell | Notes |
|---|---|---|---|
| runA | JSON | Git Bash | |
| runB | exit 2 + stderr | Git Bash | |
| runC | JSON | PowerShell (`"shell": "powershell"`) | |
| runD | exit 2 + stderr | PowerShell | |
| runE | JSON | Git Bash | Git removed from PATH; Claude Code still found Git Bash |
| runE2 | exit 2 + stderr | PowerShell | Only the PowerShell tool (`--disallowedTools Bash`, `CLAUDE_CODE_USE_POWERSHELL_TOOL=1`) |
| runF | JSON | Git Bash | `acceptEdits` plus allow rules `Bash(echo *)` and `PowerShell(echo *)` |
| runI | JSON (ask) | Git Bash | **Interactive** session in `auto` mode, run by the owner. The prompt showed the reason; the owner answered No. PermissionRequest fired; no PostToolUse or PostToolBatch followed |

Not covered: a machine with no Git for Windows installed at all (runE2 is the closest
documented setup).

## `configchange/`: ConfigChange (interactive, run by the owner)

One interactive session with a one-session test plugin whose ConfigChange hook recorded its
stdin and blocked only a settings file containing a test marker (`{"decision":"block",
"reason":…}`, exit 0). While the session ran, the owner rewrote the project's
`.claude/settings.local.json` from a separate PowerShell window five times, setting an `env`
value that a Bash `echo` then printed.

- ConfigChange fired for every external write (5 writes, 5 events), about a second later.
- The payload names the source and the file, never its content.
- The block reply worked: where a command ran afterwards, the session still used the previous
  value. No message was shown to the user.
- The blocked content stayed in the file on disk.
- Settings written while no session was running fired no event and were loaded when the
  next session started.

`observed.sessionUsedAfterwards` is `null` where no command ran before the next change.

## Sanitizing

Before these files were added: the user name, machine name, real paths and the per-project
temp folder hash were replaced with `<user>`, `<host>`, `C:\project`, `<tmp>` and `<hash>`.
Session, prompt, tool-use, agent and task ids were replaced with fake ids of the same
format, consistently, so pairs still match. `test/fixtures.test.ts` scans every file for
identifying data and fails if any is found.
