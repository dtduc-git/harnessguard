# State of AI-agent workflows in the wild

_Generated 2026-09-13T06:48:43.615997+00:00 with harnessguard 0.1.0._

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
- **51.6%** have at least one rule-of-two finding
- **44.2%** combine untrusted events with runner secrets or write permissions (HG001/HG003)
- **5.3%** interpolate attacker-controlled event data into agent steps (HG002)
- **5.3%** run an agent on `pull_request_target` (HG004)
- **44.2%** are triggered by at least one event carrying attacker-controlled content
- Of the privilege-combining files, **38.9%** restrict triggering with `github.actor` / `author_association` guards — reduced, not eliminated, exposure

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

## Caveats

- GitHub code search returns best-match results, not a uniform random sample; popularity and recency skew the corpus.
- Workflows are point-in-time snapshots; a repo can fix a finding later.
- Heuristic rules trade precision for recall; counts are a lower bound on real risk signals, not a per-repo verdict, and not every flagged workflow is exploitable (mitigations may exist outside the file).
- Agent detection is pattern-based (known actions and CLI invocations); custom or renamed integrations are not counted.
- Job-level guards (e.g. actor allowlists in `if:` conditions) are not evaluated; some flagged workflows restrict who can trigger them, which reduces but does not eliminate the injection surface.

