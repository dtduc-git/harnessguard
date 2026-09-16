# We scanned 337 AI-agent CI workflows on GitHub. 44% mix untrusted input with secrets or write tokens.

_2026-09-13 · research_

In 2026 the AI coding agent moved out of the editor and into the CI runner.
Claude Code Action, Gemini CLI Action, Codex, Copilot's coding agent and a
long tail of review bots now run inside GitHub Actions — they read issues,
pull request titles and comments, and act on them with the runner's
credentials.

That combination is the attack surface researchers keep hitting: **Comment and
Control** (April 2026) hijacked three vendor agents through a PR title,
**Black Hat USA 2026** followed with a CVSS 10.0 in the Gemini CLI Action, and
Microsoft's MSRC disclosed a path from a public issue to `/proc/self/environ`
in Claude Code Action. The common thread is Microsoft's **Agents Rule of Two**:
never combine untrusted input, privileged access, and external communication in
one workflow.

We built [harnessguard](https://github.com/dtduc-git/harnessguard), a static
linter for exactly that surface, and used it to look at what is actually in the
wild.

## What we did

We sampled public GitHub Actions workflow files matching known agent actions
via the GitHub code search API (four queries, best-match results), kept only
files directly under `.github/workflows/`, downloaded them, and analyzed them
with the harnessguard rule engine. Only files where the engine detected at
least one agent step are counted.

**Sample: 337 agent workflow files from 255 repositories.** The full
methodology, the aggregate report and the script are in the repo:
[`research/state-of-agent-workflows.md`](../research/state-of-agent-workflows.md) ·
[`scripts/ecosystem_scan.py`](../scripts/ecosystem_scan.py).

## The headline numbers

| Signal | Share of agent workflow files |
| --- | --- |
| At least one rule-of-two finding | **51.9%** |
| Untrusted events + secrets or write permissions (HG001/HG003) | **44.2%** |
| Triggered by an event carrying attacker-controlled content | **44.2%** |
| Shell / network tool grants on the agent (HG005) | **15.4%** |
| Agent runs on `pull_request_target` (HG004) | **5.3%** |
| Attacker-controlled event data interpolated into the agent (HG002) | **5.3%** |
| Untrusted checkout ref mounted into the agent's workspace (HG006) | **1.5%** |

Of the files that combine untrusted events with privilege, **66% carry no
actor or author-association guard at all**.

## The comment-triggered agent is the default shape

116 files are triggered by `issue_comment`, 97 by `issues`. That is the shape
the vendor templates ship in — an agent that reacts when someone writes
`@claude` or `@gemini` on an issue or PR. The hardened template guards the
job:

```yaml
on:
  issue_comment: { types: [created] }
jobs:
  agent:
    if: |
      contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'),
               github.event.comment.author_association) &&
      contains(github.event.comment.body, '@claude')
```

The unguarded copy — same agent, same `secrets.ANTHROPIC_API_KEY`, no `if:` —
is one deleted line away, and two thirds of the privilege-combining files in
our sample are that version. A public comment becomes instructions an agent
obeys, with the runner's credentials in scope.

## `pull_request_target` never left

18 files run an agent on `pull_request_target`, the trigger that executes in
the base repository context with secrets available even for fork pull requests.
It is the classic pwn-request pattern with a new amplification: whatever the
fork's PR text says is now instructions to a privileged agent. Five files go
further and check out the fork's head ref into the job the agent operates on
(HG006).

## We fixed the tool because of the data

The guard split was the sharpest finding, so harnessguard v0.2 recognizes
actor allowlists, `author_association` checks and `fromJSON` conditions — and
downgrades HG001/HG003 one level instead of ignoring the residual risk. v0.3
added HG006 (untrusted checkout refs) and taught HG001 to see secrets exposed
via workflow-level `env:`, both gaps surfaced by scanning real files. This is
how we want the tool to evolve: rule changes driven by the corpus, not by
imagination.

## Check your own repo in 30 seconds

```bash
uvx harnessguard scan .
```

Static, local-first, deterministic: it never executes your workflows or your
agents, and nothing leaves your machine. For CI:

```yaml
- uses: dtduc-git/harnessguard@main
  with:
    fail-on: high
```

SARIF output plugs into GitHub code scanning, so findings appear in the PR
that introduced them.

## Caveats

This is a best-match sample, not a uniform random draw; popularity and
recency skew it. Workflows are point-in-time snapshots, heuristic rules trade
precision for recall, and the numbers are a lower bound on risk signals — not
a verdict on any repository. Agent detection is pattern-based, and mitigations
may exist outside the file. No repository is named in the dataset; raw
per-repo results are intentionally not published.

## Run it yourself

The whole pipeline is reproducible:

```bash
git clone https://github.com/dtduc-git/harnessguard
cd harnessguard
uv sync --all-groups
uv run python scripts/ecosystem_scan.py --per-query 150
uv run python scripts/chain_scan.py
uv run python scripts/remediation_scan.py
```

## Update: artifact trust chains (pass 2)

Pass 2 pointed the same corpus at a different question: not "which agent steps
are exposed" but "where do repositories cross a trust boundary between
workflows". Re-scanning the **full** workflow directory of all 255 repos for
the Cordyceps pattern (attacker-triggered producer uploads artifact → a
privileged `workflow_run` consumer fetches it):

- **47.5%** of repositories upload artifacts from workflows an attacker can
  trigger (`pull_request`, comments, issues)
- **5.5%** carry the full chain across two workflows
- **100% of the chains run no AI agent on either side** — agent-only scanning
  and per-file linting never look there
- The findings collapse into a single inherited upstream template — fork
  propagation keeps the pattern alive at scale

Pass-2 aggregates live in the same report:
[State of AI-agent workflows](research/state-of-agent-workflows.md).

## Update: reusable workflow chains, MCP hygiene, and a 3-day re-scan (v0.6)

Three more questions against the same corpus, with three new rules:

- **Reusable workflow chains (HG008)** — untrusted-triggered workflows that pass
  secrets into an agent-bearing local reusable workflow. **20 repositories**
  carry the chain; **17 of 20** descend from a single dispatch template
  (`secrets: inherit` into `gemini-*.yml` callees). An upstream
  author-association guard downgrades 52 of 54 findings to medium; the two
  remaining high findings (a `pull_request_target` review chain and an
  issue-comment engineer chain) were hand-validated.
- **MCP hygiene (HG010)** — agent steps launching MCP servers from unpinned
  packages (`uvx ols-mcp`, `npx -y mcp-remote`) or pointing at plaintext
  `http://` endpoints. Small but real: five configurations in the agent corpus,
  all unpinned packages, no pins anywhere.
- **Pass 3: re-scan after publication** — the 2026-09-13 corpus was re-fetched
  and re-scanned with the same engine: **336 of 337 files still exist, 97%
  are byte-identical, zero findings were fixed and zero introduced in three
  days.** Publication alone does not move a corpus; we will re-run this
  monthly (the corpus is private, so it runs locally) and report the numbers
  as they move.

Two adoption features ship alongside: `--baseline` (record today's findings,
fail CI only on new ones — for repos with existing debt) and `harnessguard mcp`
(a local stdio MCP server so coding agents can lint the workflows they
generate before writing them).

---

harnessguard is Apache-2.0. Rules are YAML; PRs welcome:
https://github.com/dtduc-git/harnessguard
