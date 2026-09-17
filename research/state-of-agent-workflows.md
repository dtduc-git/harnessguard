# State of AI-agent workflows in the wild

_Generated 2026-09-13T07:19:21.192910+00:00 with harnessguard 0.3.0._

## Methodology

Public GitHub Actions workflow files matching known AI-agent actions were sampled via the GitHub code search API (queries below, best-match results), filtered to files directly under `.github/workflows/`, downloaded from raw.githubusercontent.com, and analyzed with the harnessguard rule engine. Only files where the engine detected at least one agent step are counted. All stats are aggregate; no repository is named in this report.

| Query | Candidates requested |
| --- | --- |
| `claude-code-action path:.github/workflows` | 96 |
| `run-gemini-cli path:.github/workflows` | 112 |
| `codex-action path:.github/workflows` | 141 |
| `copilot-coding-agent path:.github/workflows` | 143 |

## Headline

- Agent workflow files analyzed: **337** from **255** repos
- **51.9%** have at least one rule-of-two finding
- **44.2%** combine untrusted events with runner secrets or write permissions (HG001/HG003)
- **5.3%** interpolate attacker-controlled event data into agent steps (HG002)
- **5.3%** run an agent on `pull_request_target` (HG004)
- **44.2%** are triggered by at least one event carrying attacker-controlled content
- Of the privilege-combining files, **33.6%** restrict triggering with `github.actor` / `author_association` guards — reduced, not eliminated, exposure

## Sample

- Files downloaded and parsed: **490**
- Files with a detected agent step: **337**
- Repositories: **255**
- Download / parse failures: 2

### Untrusted trigger mix (agent files)

| Event | Files |
| --- | --- |
| `issue_comment` | 116 |
| `issues` | 97 |
| `pull_request_target` | 18 |

## Findings by rule

| Rule | Files affected | Share of agent files |
| --- | --- | --- |
| HG001 | 148 | 43.9% |
| HG003 | 124 | 36.8% |
| HG005 | 52 | 15.4% |
| HG004 | 18 | 5.3% |
| HG002 | 18 | 5.3% |
| HG006 | 5 | 1.5% |

<!-- chain-scan:start -->

## Artifact trust chains (pass 2)

_Generated 2026-09-13T14:42:54.958659+00:00 with harnessguard 0.4.0. Raw per-repo results are private; aggregates only._

Pass 1 sampled agent workflow files in isolation. HG007 (the Cordyceps pattern) needs the opposite view: the full `.github/workflows` directory of every repository in the pass-1 corpus, because the attacker-triggered producer and the privileged `workflow_run` consumer usually contain no agent step at all.

### Headline

- Repositories with retrievable workflows: **255** (of 255 in the pass-1 corpus)
- Workflow files parsed: **3342**
- **47.5%** upload artifacts from workflows an attacker can trigger (`pull_request`, comments, issues)
- **5.5%** have the full chain: attacker-triggered producer plus a privileged artifact consumer (**14** repositories, 14 HG007 findings)
- **100.0%** of the chains run no AI agent on either side — invisible to agent-only scanners and to single-file linters alike
- The chains collapse into **1 distinct producer→consumer template pair(s)**; the largest family appears in **14 repositories** (fork propagation)

### HG007 findings by severity

| Severity | Findings |
| --- | --- |
| high | 14 |

### Caveats

- Same corpus as pass 1 (GitHub code search, best-match, not a uniform random sample); workflow snapshots are from the default branch at scan time.
- Chain detection is name-based (`workflow_run.workflows` ↔ workflow name or file stem) and conservative on purpose: an unmatched producer name produces no finding.
- Environment-gated consumers are downgraded one severity level, not cleared; a chain finding is a trust-boundary signal, not a per-repo verdict.
- The corpus is fork-heavy: a few upstream templates are inherited by many forks, so repository counts overstate the number of independent implementations.

<!-- chain-scan:end -->

## Reusable workflow chains (pass 2.5)

_Generated 2026-09-16 with harnessguard 0.5.0, HG008 applied to the same 255-repo corpus as pass 2._

The inverse of pass 2: instead of asking whether a privileged job consumes untrusted artifacts, ask whether an untrusted-triggered workflow passes secrets into an agent-bearing local reusable workflow (`./` or `$/` reference). Per-file scanners see two innocuous files; the Rule of Two violation is the composition.

### Headline

- **20 caller files across 20 repositories** pass secrets from an untrusted trigger into a reusable workflow that runs an agent
- **1 dominant template**: the Gemini CLI Action dispatch workflow (`gemini-dispatch.yml` and variants) accounts for **17 of 20** — comments or issues dispatch into `gemini-*.yml` callees with `secrets: inherit`
- **2 remain high** after guard analysis: one `pull_request_target` Codex review chain and one issue-comment Codex engineer chain; both pass an explicit secrets mapping with no visible trigger guard
- The remaining high finding uses the newer `$/.github/workflows/` self-reference syntax, which static tooling that only understands `./` will not resolve
- **100%** of chains contain the agent on the callee side — the opposite of pass 2, where every artifact chain was agent-free

### HG008 findings by severity

| Severity | Findings |
| --- | --- |
| high | 2 |
| medium (indirect `needs:` guard upstream) | 52 |

### MCP configuration (HG010)

- **5 agent workflow files** launch MCP servers without an immutable version pin (`uvx ols-mcp`, `npx -y mcp-remote`, `@upstash/context7-mcp`); none of the observed MCP configurations pin a version
- No plaintext non-loopback MCP endpoints were observed in this corpus

### Caveats

- Caller→callee resolution is name-based and conservative: an unresolvable or non-local `uses:` target produces no finding.
- The corpus is fork-heavy; **17 of 20** caller files descend from a single upstream template, so repository counts overstate independent implementations.
- The indirect-guard downgrade is a one-hop heuristic: upstream jobs guarded in scripts rather than `if:` conditions are not detected, and an upstream guard does not necessarily cover every event path.
- Agent detection is pattern-based; renamed or wrapped agent invocations inside callees are not counted.

<!-- remediation-scan:start -->

## Re-scan after publication (pass 3)

_Generated 2026-09-16T14:34:22.623413+00:00 with harnessguard 0.6.0. Same corpus as pass 1 (agent-bearing workflow files); each file re-fetched from its repository and compared against the 2026-09-13 snapshot with the same engine._

### Headline

- Files re-checked: **336** of 337 (1 no longer retrievable at the same path)
- **326** files byte-identical to the 2026-09-13 snapshot (97.0%) — the corpus is largely static
- **0** files fixed every finding they previously had; **0** gained at least one new finding
- Files carrying at least one finding: **176 → 176** against the same rule set

### Findings by rule, before → after

| Rule | Files (snapshot) | Files (today) |
| --- | --- | --- |
| HG001 | 148 | 148 |
| HG002 | 20 | 20 |
| HG003 | 124 | 124 |
| HG004 | 18 | 18 |
| HG005 | 52 | 52 |
| HG006 | 5 | 5 |
| HG010 | 1 | 1 |

### Caveats

- The window between snapshot and re-scan is three days; a low change rate is expected and does not measure the blog's effect.
- Files live on default branches; edits can be unrelated to security (dependency bumps, renames, refactors), and repositories can be archived.
- Repo-level chain rules (HG007–HG009) cannot be evaluated per file and are excluded from this comparison; HG010 is included.

<!-- remediation-scan:end -->

<!-- pass4-scan:start -->

## Fresh sample (pass 4)

_Generated 2026-09-17T11:17:52.723061+00:00 with harnessguard 0.6.1. New code-search queries targeting MCP configuration, agentic-workflow surfacing and newer agent CLIs. Per-file rules only; repository-level chain rules (HG007–HG009) are measured by the scans above._

| Query | Candidates selected |
| --- | --- |
| `mcpServers path:.github/workflows` | 85 |
| `mcp-config path:.github/workflows` | 61 |
| `"mcp-remote" path:.github/workflows` | 98 |
| `"agentic workflow" path:.github/workflows` | 11 |
| `claude-code-base-action path:.github/workflows` | 90 |
| `"qwen-code" path:.github/workflows` | 96 |
| `cursor-agent path:.github/workflows` | 63 |

### Headline

- Agent workflow files: **96** from **81** repos — **11** already present in the pass-1 corpus
- **60.4%** have at least one rule-of-two finding
- **41.7%** combine untrusted events with runner secrets or write permissions (HG001/HG003)
- **3.1%** interpolate attacker-controlled event data into agent steps (HG002)
- **3.1%** run an agent on `pull_request_target` (HG004)
- **21.9%** launch unpinned MCP servers or plaintext MCP endpoints (HG010)

### Findings by rule

| Rule | Files affected | Share of agent files |
| --- | --- | --- |
| HG001 | 40 | 41.7% |
| HG005 | 40 | 41.7% |
| HG003 | 37 | 38.5% |
| HG010 | 21 | 21.9% |
| HG006 | 5 | 5.2% |
| HG004 | 3 | 3.1% |
| HG002 | 3 | 3.1% |

### Caveats

- New queries change what the sample selects; percentages are not directly comparable with pass 1 — compare rule shares, not absolute counts.
- The MCP queries select files that *mention* MCP configuration even when no agent runs in them; only files with a detected agent step are counted.
- HG010 fires on unpinned packages and non-loopback plaintext endpoints; pinned servers and loopback endpoints are not counted.
- Best-match sampling; the corpus is fork-heavy, so repository counts overstate independent implementations.

<!-- pass4-scan:end -->

## Caveats

- GitHub code search returns best-match results, not a uniform random sample; popularity and recency skew the corpus.
- Workflows are point-in-time snapshots; a repo can fix a finding later.
- Heuristic rules trade precision for recall; counts are a lower bound on real risk signals, not a per-repo verdict, and not every flagged workflow is exploitable (mitigations may exist outside the file).
- Agent detection is pattern-based (known actions and CLI invocations); custom or renamed integrations are not counted.
- Job-level guards (actor allowlists, author-association checks) are recognized for HG001/HG003 and downgrade those findings one level; other rules do not consider guards, and a guard still leaves compromised-account and indirect-injection risk.

