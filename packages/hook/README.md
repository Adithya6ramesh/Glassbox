# @glassbox-ai/hook

The Glassbox Claude Code hook: `glassbox-hook <event> [--home <dir>]`. It checks every tool
call with `@glassbox-ai/engine` before it runs and records what happened. It never uses the
network and never starts other processes.

Status: core only. The plugin manifest, `hooks.json`, installer and uploader come later.

## Replies (PreToolUse)

| Engine verdict | Reply |
|---|---|
| allow | nothing (exit 0): Claude Code's own permission flow still applies |
| warn | nothing by default (see the flag below) |
| ask | JSON `permissionDecision: "ask"` with the reason; Claude Code shows its prompt |
| deny | JSON `permissionDecision: "deny"` with the reason; Claude reads it |

JSON on stdout is the main method. Exit 2 is used only if writing the JSON fails; the stderr
reason is then reduced to plain words, because Claude Code also shows Claude the hook's
command line in that case. The hook never rewrites tool input.

If the hook can't check a call (bad input, the internal 800 ms deadline, an internal error),
read-only built-ins (`Read`, `Glob`, `Grep`, `WebSearch`, `TodoWrite`) are allowed and every
other tool is denied.

## Outcomes

Each decision is kept open per session and closed by whatever happens next:

| What happened | Outcome |
|---|---|
| PostToolUse | Ran |
| PostToolUseFailure | Ran; failed (with the exit code for shell tools) |
| PostToolBatch shows our deny | Blocked |
| PostToolBatch shows exactly our ask reason (`-p` mode: nobody to ask) | Blocked (no one to ask) |
| Our ask, then nothing (the user said No, which ends the turn) and the turn ends | Asked; not run |
| PostToolBatch shows a refusal for a call we allowed | Refused by Claude Code; not run |
| Nothing, for a call we allowed | Outcome unknown |

Pairing uses Claude Code's `tool_use_id`. A different input at PostToolUse than the one
checked at PreToolUse is recorded as `CP-HOOK-001` (another hook rewrote it).

## Unverified outputs: off by default

`systemMessage`, `additionalContext` and every PostToolUse output field have not been
verified against a real Claude Code yet. They are only sent when `~/.glassbox/config.json`
contains `{ "experimental": { "unverifiedHookOutputs": true } }`. With the flag off, an engine
result rewrite is recorded as not applied.

## Local state (`~/.glassbox`)

`config.json`, `remembered.json` (both written by the CLI), `device-salt`,
`sessions/<id>/signals.jsonl`, `sessions/<id>/pending/<call>.json`, `spool/*.jsonl`. Events are
metadata only: command name and flags (never argument values), project-relative paths, hosts,
pattern lengths, rule ids. Finding evidence is not recorded.

## Timing

`node packages/hook/scripts/timing.mjs [--entry main.js|bundle/main.mjs]` measures p50/p95/p99
per hook process, warm and cold (fresh copy of the install). CI runs it on Linux and Windows
(`hook-timing` workflow). Target: p95 ≤ 150 ms for an allow.

## Bundle

The hook ships as one file, `dist/bundle/main.mjs`, built with rolldown (a dev dependency; it
never ships). The bundle is built in CI only. CI runs the whole hook test suite against the
source and again against the bundle (`GLASSBOX_HOOK_TARGET=bundle`). The `hook-release`
workflow builds and tests the bundle and writes its SHA-256 into the release notes; it publishes
nothing. Node's compile cache is not used: it made the first run after an install much slower on
Windows.
