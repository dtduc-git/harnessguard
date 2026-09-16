# harnessguard

Static hardening linter for GitHub Actions workflows that run **AI agents**.

Agents in CI (Claude Code Action, Gemini CLI Action, Codex, Copilot agents and
friends) read attacker-controlled text — issue bodies, PR titles, comments —
while the runner holds secrets and write tokens. That combination is the new
CI/CD supply-chain attack surface: a public comment becomes instructions the
agent obeys.

harnessguard enforces Microsoft's **[Agents Rule of Two](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case)**:
an AI-powered workflow must never combine untrusted input, privileged access,
and external communication. It runs as a **static, deterministic** check in
pull requests — it never executes your workflows or your agents.

## Why

Real incidents, all from 2026:

- **Comment and Control** (April 2026) — hijacked Claude Code Security Review,
  Gemini CLI Action and Copilot Agent via PR titles / issue bodies; leaked
  `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` and `GITHUB_TOKEN` through public
  comments.
- **Black Hat USA 2026** (August) — an unprivileged GitHub issue reached CI
  runner secrets in the vendors' own repositories; Gemini CLI Action got
  CVE-2026-12537 (CVSS 10.0).
- **MSRC** — Claude Code Action's Read tool reached `/proc/self/environ`;
  fixed in 2.1.128.

Existing Actions linters (`zizmor`, `actionlint`, `poutine`…) are excellent
but agent-blind: they don't model "this step is an LLM that will obey text."

## Research

We sampled **337 public agent workflow files** (255 repos) via the GitHub code
search API: **44.2% combine untrusted events with runner secrets or write
permissions**, and 61% of those carry no actor-association guard in the
workflow file. Aggregates only — no repo is named.

Pass 2 re-scanned the **full workflow set** of the same 255 repos for
cross-workflow artifact chains (HG007): **5.5% carry the chain**, and every
chain detected runs **no agent on either side** — a blind spot for agent-only
scanners and per-file linters alike.

Pass 2.5 looked for the mirror pattern (HG008): untrusted-triggered workflows
that pass secrets into an agent-bearing reusable workflow. **20 repos** carry
the chain; **17 of 20** come from the Gemini CLI Action dispatch template.
→ [State of AI-agent workflows in the wild](research/state-of-agent-workflows.md)
· reproduce with `uv run python scripts/ecosystem_scan.py` and
`uv run python scripts/chain_scan.py`

## Install

```bash
pip install harnessguard
# or from source
uv sync && uv run harnessguard --version
```

## Usage

```bash
# scan the current repo (finds .github/workflows/)
harnessguard scan .

# fail CI on high and above, write SARIF for code scanning
harnessguard scan . --fail-on high --sarif harnessguard.sarif

# machine-readable output
harnessguard scan . --format json

# adopt on an existing repo: record current findings, then only fail on new ones
harnessguard scan . --format json > baseline.json
harnessguard scan . --baseline baseline.json --fail-on high

# let coding agents lint the workflows they generate (stdio MCP server)
harnessguard mcp

# list rules
harnessguard rules list
```

Exit code is 1 when findings at or above `--fail-on` exist. `--fail-on none`
reports without failing.

### MCP server

`harnessguard mcp` serves the scanner over stdio MCP (read-only, no network):
`scan_repository`, `scan_workflow` (lint YAML before writing it) and
`list_rules`. Wire it into any MCP client:

```json
{ "mcpServers": { "harnessguard": { "command": "uvx", "args": ["harnessguard", "mcp"] } } }
```

### GitHub Action

```yaml
name: harnessguard
on: [push, pull_request]

jobs:
  harnessguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: dtduc-git/harnessguard@v0.4.0
        with:
          fail-on: high
```

## Rules

| Rule  | Severity | What it catches |
|-------|----------|-----------------|
| HG001 | critical | Agent step on untrusted events with secrets in scope (job or workflow env) |
| HG002 | high | Attacker-controlled event data interpolated into an agent step |
| HG003 | high | Agent step on untrusted events with write permissions |
| HG004 | high | Agent step in a `pull_request_target` workflow |
| HG005 | medium | Agent step with shell/network tool grants or egress commands |
| HG006 | high | Agent job checks out an attacker-controlled ref |
| HG007 | high | Privileged `workflow_run` job consumes artifacts from untrusted-triggered workflows (Cordyceps chain) |
| HG008 | high | Untrusted-triggered workflow passes secrets into an agent-bearing reusable workflow |
| HG009 | high | Agent step consumes artifacts from an untrusted-triggered workflow |
| HG010 | medium | Agent step launches unpinned MCP servers or plaintext MCP endpoints |

Findings map to the OWASP Top 10 for Agentic Applications (ASI01–ASI05).
Jobs whose `if:` restricts triggering via `github.actor` / `author_association`
guards get HG001/HG003 downgraded one level — reduced exposure is still
flagged, just at lower severity.
Rules are data — YAML in `src/harnessguard/rules_data/` — and checks are small
named functions in `checks.py`. Add your own with `--rules-dir`.

## Design principles

- **Never executes anything.** No workflow runs, no agent calls, no network.
- **Local-first.** No account, no telemetry, no SaaS.
- **Deterministic.** Same input → same findings; no LLM in the detection path.
- **Rules as data.** Extend coverage without touching the engine.

## Non-goals

- Not a general-purpose Actions linter — use zizmor alongside it.
- No runtime enforcement or proxy — that is a different (complementary) tool.
- Not GitLab/Jenkins (yet).

## References

- Microsoft Security Blog — *Securing CI/CD in an agentic world* (Agents Rule
  of Two), June 2026
- CSA — *Comment and Control: GitHub AI Agents as Credential Exfiltrators*,
  April 2026
- OWASP — Top 10 for Agentic Applications 2026

## License

Apache-2.0
