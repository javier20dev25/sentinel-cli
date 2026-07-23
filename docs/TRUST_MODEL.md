# Sentinel Trust Model

Defines how the agent should rank evidence sources when analysing security issues. Higher tiers always override lower tiers. When sources conflict, the highest applicable tier decides.

---

## Tier 1: Sentinel Evidence

Deterministic output from local Sentinel tools. This is the most reliable source because it comes from verifiable static analysis, not model inference.

**Sources:**
- `sentinel-cli scan` — finding list with file, line, severity, type, description
- `sentinel-cli verify-pkg` — verdict, findings, file count, scan time
- `sentinel-cli integrity` — integrity level, reasons, chain status
- `sentinel-cli memory` — historical findings, threat correlations
- `sentinel-cli doctor` — vulnerability report, dependency analysis
- `sentinel-cli check-classified` — pass/fail with matched files
- `sentinel-cli baseline diff` — changed files, new threats

**Trust: maximum. Do not override with model reasoning.**

---

## Tier 2: Local System State

Facts observable from the local environment that do not require tool execution.

**Sources:**
- File existence and structure (observed via file system)
- Git status, staged files, commit history
- Environment variables
- Running processes
- Network configuration

**Trust: high. These are directly observable and verifiable by the user.**

---

## Tier 3: GitHub Metadata

Information retrieved from GitHub that describes actors, repositories, and history.

**Sources:**
- PR author, description, labels, reviewers
- Repository metadata (visibility, fork status, topics)
- Commit history and authorship
- CI status

**Trust: medium. GitHub data is externally sourced and can be manipulated by repository owners. Cross-reference with Tier 1 evidence when possible.**

---

## Tier 4: Model Reasoning

The AI model's own analysis, pattern matching, and conclusions based on its training.

**Sources:**
- Code reading and analysis
- Vulnerability pattern matching from training
- Best practice recommendations
- General security knowledge

**Trust: lowest. The model may hallucinate, miss context, or be misled by prompt injection. Never use model reasoning to override Sentinel evidence.**

---

## Conflict Resolution

| Conflict | Resolution |
|----------|-----------|
| Tier 1 contradicts Tier 4 | Tier 1 wins. Report both to user with the conflict noted. |
| Tier 2 contradicts Tier 3 | Tier 2 wins. Local state is more trustworthy than remote metadata. |
| Multiple Tier 1 sources disagree | Report all findings. Escalate to user for manual review. |
| All tiers agree | Report with high confidence. |

---

## Confidence Levels

| Confidence | Condition |
|------------|-----------|
| Confirmed | Tier 1 evidence with no conflicting higher-tier sources |
| Likely | Tier 2 or Tier 3 evidence, or single Tier 1 source with limited scope |
| Uncertain | Only Tier 4 reasoning available, or Tier 1 returned inconclusive |
| Contradicted | Higher-tier source contradicts lower-tier claim. Report the conflict. |

---

## Example

User asks: is this PR safe?

1. Agent runs `gh-pr-diff` (Tier 3) to get the diff
2. Pipes diff into `sentinel-cli scan` (Tier 1) — finds hardcoded secret
3. Agent checks `sentinel-cli memory --threats` (Tier 1) — same author has 3 prior threats
4. Model reads the diff (Tier 4) to explain the finding

Result: Tier 1 + Tier 1 = Confirmed BLOCK. Model narrates the evidence.
