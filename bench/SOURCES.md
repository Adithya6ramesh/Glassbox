# Public-source benchmark corpus

`bench/public/dev.json` and `bench/public/holdout.json` hold 2,434 cases taken from published
datasets and projects. No case was written for Glassbox. Every case records its `source` and
`license`.

**The cases are inert data.** Commands are strings that `bench/public-run.mjs` passes to
`checkToolCall`, which only analyzes them. Nothing may execute them: not T-DIFF
(`packages/shell-difftest`, which only runs its own fixed corpus, and a test checks it never
reads `bench/public`), not a script, not a person copying them to a shell. Many are real attack
techniques (disk wipes, persistence, exfiltration).

## Sources and licenses

| source | what is used | license | cases |
|---|---|---|---|
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | `text`, `label` 1 = injection, 0 = benign | Apache-2.0 | 150 + 150 |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | `text` (all injections) | MIT | 150 |
| [reshabhs/SPML_Chatbot_Prompt_Injection](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | `User Prompt`, `Prompt injection` 1/0 (first 500 rows) | MIT | 150 + 95 |
| [microsoft/BIPIA](https://github.com/microsoft/BIPIA) | `benchmark/{text,code}_attack_{train,test}.json`: the attack instructions only, not the third-party contexts | MIT | 250 |
| [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | `test_cases_{dh,ds}_base.json`: tool responses carrying an attacker instruction (one per instruction); each user tool's response template with the placeholder removed (benign) | MIT | 62 + 17 |
| [zhiqiangwang4/MCPTox-Benchmark](https://github.com/zhiqiangwang4/MCPTox-Benchmark) | `pure_tool.json`: the 485 poisoned tool definitions (server name, tool name, description) | CC-BY-4.0 | 485 |
| [AIS2Lab/MCPSecBench](https://github.com/AIS2Lab/MCPSecBench) | `code/maliciousadd.py`: docstrings of `add`, `modify`, `m_check`, `aft_check`, which its README uses for tool poisoning and shadowing | MIT | 4 |
| [github/github-mcp-server](https://github.com/github/github-mcp-server) | `pkg/github/__toolsnaps__/*.snap`: real tool definitions (benign) | MIT | 146 |
| [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | `atomics/Indexes/index.yaml`: `sh`/`bash` and `powershell` executor commands, default arguments filled in | MIT | 146 + 59 |
| [tldr-pages/tldr](https://github.com/tldr-pages/tldr) | example commands of a fixed list of everyday developer tools (benign) | CC-BY-4.0 | 570 |

**Attribution (CC-BY-4.0).** MCPTox: © the MCPTox contributors, from
https://github.com/zhiqiangwang4/MCPTox-Benchmark, CC BY 4.0
(https://creativecommons.org/licenses/by/4.0/). Changed: each poisoned tool is wrapped in a
one-tool server manifest with an empty input schema. tldr-pages: © the tldr-pages team and
contributors, from https://github.com/tldr-pages/tldr, CC BY 4.0. Changed: `{{placeholder}}`
markers are replaced by their text.

**Checked and not used:**
- GTFOBins and LOLBAS: GPL-3.0. Their content can't be copied into this Apache-2.0 repository.
- invariantlabs-ai/mcp-injection-experiments, harishsg993010/damn-vulnerable-MCP-server and
  xTRam1/safe-guard-prompt-injection: no license, so all rights are reserved.
- The rest of BIPIA: its emails, tables and Q&A contexts come from third-party datasets under
  their own licenses (some CC-BY-SA).
- MCPSecBench's `main.py`: a GUI-automation client, not a tool list, so it has no benign tools.
- AgentDojo (MIT): its injection tasks are Python code, not data.

## Labelling rules (fixed before the engine was run on any case)

Labels come from each source's own taxonomy and from the engine spec, never from engine output.

- **Prompt-injection datasets** (results surface): the source's injection label → `stop`, its
  benign label → `benign`. Each text is the content of a web-fetch tool result.
- **MCPTox and MCPSecBench** (manifest surface): poisoned tools → `stop`, meaning grade C, D or F.
  github-mcp-server tools → `benign`, meaning grade A or B. Each tool is its own one-tool server,
  graded with no known tools from other servers.
- **Atomic Red Team** (call surface), by ATT&CK technique:
  - `stop` (should ask or deny):
    - every `exfiltration`-tactic test;
    - impact: T1485, T1490, T1561, T1529, T1489, T1486, T1531;
    - persistence locations: T1053, T1543, T1547, T1037, T1098.004, T1546.004, T1546.013;
    - impair defenses: T1562.
  - `warn` (anything but allow): clearing logs and history (T1070.001–.003) and reading
    credential files (T1552.001, T1552.004). This is the spec's decision: these warn.
  - All other techniques are left out (discovery, collection, execution…): Glassbox doesn't aim
    to stop them, and whether they are attacks depends on intent.
  - `sh`/`bash` tests run as the Bash tool on Linux, `powershell` tests as the PowerShell tool on
    Windows. `command_prompt` and `manual` tests are left out (no cmd.exe analyzer).
- **tldr-pages** (call surface): every example on the pages of a fixed tool list → `benign`.
  The list is in the builder: git, npm, docker, kubectl, coreutils, and some PowerShell cmdlets.
  Some examples are legitimately risky (`git push --force`, `rm -r`, `docker rm`), and asking
  for them is by design. So the benign ask and deny counts are reported separately, and the
  false-positive rate on this source is an upper bound.

## Changes to the source text

- Atomic Red Team: Slack webhook URLs are replaced by `hooks.slack.com/services/REDACTED`, because
  no credential-shaped literal may be committed to this repository. The network call stays visible.

## Sampling and split

- Duplicates are removed per source and label.
- At most 150 cases are kept per (source, label), chosen in SHA-256 order of a salted key.
- Each case's split comes from the SHA-256 of its id: 70% `dev.json`, 30% `holdout.json`.

## How the holdout is used

- Tuning looks only at `dev.json` (`pnpm run bench:public`).
- The holdout is scored once with `pnpm run bench:public --final`, which writes
  `bench/public/FINAL.json` and `FINAL.md` and refuses to run again.
- After that, a new holdout needs a new corpus version.
