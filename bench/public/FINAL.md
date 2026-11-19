Engine commit 51744676c021112e3b5b4f40a7b8fe76d042fb52.

# Public-source benchmark: Sealed holdout (30%), scored once

733 cases. Sources and labelling rules: bench/SOURCES.md.

## Balanced mode

| surface · category | stop: caught | warn-group: flagged | benign: passed | benign asks | benign denies (or grade D/F) |
|---|---|---|---|---|---|
| call · destructive-shell | 12/17 (70.6%) | 9/12 (75.0%) | 0/0 (–) | 0 | 0 |
| call · everyday-powershell | 0/0 (–) | 0/0 (–) | 21/22 (95.5%) | 0 | 1 |
| call · everyday-shell | 0/0 (–) | 0/0 (–) | 135/140 (96.4%) | 5 | 0 |
| call · exfil-shell | 5/12 (41.7%) | 0/0 (–) | 0/0 (–) | 0 | 0 |
| call · powershell | 8/10 (80.0%) | 6/6 (100.0%) | 0/0 (–) | 0 | 0 |
| manifest · tool-poisoning | 131/142 (92.3%) | 0/0 (–) | 43/43 (100.0%) | 0 | 0 |
| result · result-injection | 63/249 (25.3%) | 0/0 (–) | 80/80 (100.0%) | 0 | 0 |
| **all** | 219/430 (**50.9%**) | 15/18 (83.3%) | 279/285 (**97.9%**) | 5 | 1 |

Recall (stop label) 50.9% · precision 97.3% · false-positive rate 2.1% (benign stopped: ask, deny or grade C/D/F).

## By mode (calls and results; stop label caught / benign stopped)

| mode | stop caught | benign stopped |
|---|---|---|
| strict | 95/288 (33.0%) | 23/242 (9.5%) |
| balanced | 88/288 (30.6%) | 6/242 (2.5%) |
| autopilot | 88/288 (30.6%) | 6/242 (2.5%) |
