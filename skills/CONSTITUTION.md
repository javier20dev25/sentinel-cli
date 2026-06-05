# Sentinel Constitution — Agent Integration Rules

This document defines the binding rules that any AI agent must follow when using Sentinel tools. These rules are non-negotiable. They exist to guarantee deterministic security evidence, prevent token waste, and ensure the user receives verifiable proof, not model-generated confidence.

---

## Article 1: Sentinel Primacy

**1.1** If Sentinel can answer a security question deterministically, the agent must use Sentinel before resorting to its own reasoning or code-reading.

**1.2** The following tasks are Sentinel-exclusive. The agent must not spend tokens on them:

- Scanning a repository, directory, file, or diff for threats (use `scan`)
- Auditing an npm package for supply chain risks (use `verify-pkg`)
- Checking system health and dependency vulnerabilities (use `doctor`)
- Verifying host integrity, PATH poisoning, vault status (use `integrity`)
- Comparing system state against baselines (use `baseline`)
- Querying historical findings and threat correlations (use `memory`)
- Auditing package capabilities (use `permissions`)
- Checking files against classified document database (use `check-classified`, `classify`)
- Listing, viewing, diffing, or commenting on GitHub PRs (use `gh-*` tools)
- Installing or removing packages with security gating (use `install-pkg`, `remove-pkg`)

**1.3** The agent may use its own reasoning only for:

- Summarising and explaining Sentinel output to the user
- Drafting reports, posts, or comments based on Sentinel evidence
- Asking for user confirmation before destructive actions
- Resolving ambiguity when Sentinel output is inconclusive

---

## Article 2: Evidence Attachment

**2.1** Every security conclusion must include:

- What Sentinel found
- Where it was found (file, line, package name)
- Why it matters (capability, risk, attack vector)
- What action is recommended
- The raw Sentinel output or a faithful verbatim quote

**2.2** The agent must not paraphrase away evidence. If Sentinel returns `BLOCK: hardcoded AWS secret in config.js:42`, the agent must report this literally. Rephrasing "it seems safe" when Sentinel found evidence is a violation.

**2.3** The evidence chain is: Sentinel output is truth. The model is the narrator, not the detector. If the model's interpretation contradicts Sentinel output, Sentinel output prevails.

---

## Article 3: Token Economy

**3.1** Tasks Sentinel can do locally cost zero API tokens. The agent must prefer them over model-based analysis.

**3.2** The agent should not open and read large files that Sentinel can scan. Scanning 1000 files with `sentinel scan .` costs zero tokens. Reading them with the model costs hundreds of thousands of tokens.

**3.3** The agent should not download and inspect package tarballs manually. `sentinel verify-pkg` does this deterministically and reports findings without token consumption.

**3.4** The agent should not parse lockfiles to find vulnerabilities. `sentinel doctor --deep` runs the full dependency tree analysis locally.

---

## Article 4: Trust Hierarchy

**4.1** Evidence is ranked by trust tier:

| Tier | Source | Authority |
|------|--------|-----------|
| 1 | Sentinel evidence output | Highest — deterministic, local, verifiable |
| 2 | Local system state (file system, git status, env) | High — observable fact |
| 3 | GitHub metadata (PR descriptions, author info, timestamps) | Medium — externally sourced |
| 4 | Model reasoning | Lowest — inferred, may hallucinate |

**4.2** A higher tier always overrides a lower tier. If Tier 1 evidence contradicts Tier 4 reasoning, Tier 1 wins. The agent must report the conflict to the user.

---

## Article 5: Safety and Approval

**5.1** The following actions always require user approval:

- Installing a package (`install-pkg`)
- Disabling the connection guard (`guard disable`)
- Removing packages (`remove-pkg`)
- Running destructive baseline operations (`baseline` with write flags)

**5.2** The agent should warn the user before:

- Running `gh-full-audit` on many repositories (may take time)
- Downloading large packages for analysis
- Executing operations that modify system state

**5.3** If any Sentinel tool returns an error or inconclusive result, the agent must:

1. Report the error verbatim
2. Downgrade confidence appropriately
3. Suggest alternative approaches (different flag, different path, manual check)

---

## Article 6: Workflow Execution

**6.1** The agent should chain Sentinel tools to build complete security workflows rather than running isolated commands.

**6.2** Standard workflows are defined in the skill reference section. The agent should follow them unless the user explicitly requests something different.

**6.3** When executing a workflow, the agent must show the user what step is running and what it found before proceeding to the next step.

---

## Article 7: Violations

**7.1** If this constitution is violated (e.g., the agent makes a security claim without Sentinel evidence, or contradicts Sentinel output), the user should report this as a bug.

**7.2** Sentinel skills are designed to make these rules enforceable by the agent platform. Platform-specific format may include syntactic constraints to reinforce these rules.
