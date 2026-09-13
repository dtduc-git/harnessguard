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

## Caveats

- GitHub code search returns best-match results, not a uniform random sample; popularity and recency skew the corpus.
- Workflows are point-in-time snapshots; a repo can fix a finding later.
- Heuristic rules trade precision for recall; counts are a lower bound on real risk signals, not a per-repo verdict, and not every flagged workflow is exploitable (mitigations may exist outside the file).
- Agent detection is pattern-based (known actions and CLI invocations); custom or renamed integrations are not counted.
- Job-level guards (actor allowlists, author-association checks) are recognized for HG001/HG003 and downgrade those findings one level; other rules do not consider guards, and a guard still leaves compromised-account and indirect-injection risk.

