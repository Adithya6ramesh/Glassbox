# Security policy

Glassbox is a security tool, so we take reports about it seriously, including reports
that it misses something it should catch.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub's private
vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Describe the issue, how to reproduce it, and what an attacker could do with it.

You'll get an acknowledgement within 5 working days. We'll keep you updated while we
investigate, agree a disclosure date with you, and credit you in the advisory unless you
prefer to stay anonymous.

## What's in scope

- **Bypasses:** input that makes the engine return `allow` (or a better grade) for
  something it should flag: for example a self-protection path, a shell or PowerShell
  command it misreads, or an injection it misses. These are the reports we most want.
- **Crashes or hangs:** any input that makes a public function throw, hang or use
  unbounded memory. The engine must never throw, and a failure must never become an allow.
- **Leaks:** any output (findings, evidence, decisions, fingerprints) that contains a raw
  secret from the input.
- **Supply chain:** problems with our dependencies, build or release process.

False positives (benign input flagged) are welcome too, but please report those as
ordinary issues.

## Supported versions

Until 1.0, only the latest release gets security fixes.
