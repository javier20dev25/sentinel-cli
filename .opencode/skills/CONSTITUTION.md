# Sentinel Constitution — Agent Integration Rules

This document defines the binding rules that any AI agent must follow when using Sentinel tools. These rules are non-negotiable. Violations must be reported as bugs.

---

## Article 0: Behavioral Enforcement

### 0.1 FORBIDDEN — The agent MUST NOT under any circumstances:

**A) Discover capabilities by reading source code**
- Do NOT read `src/`, `lib/`, `dist/`, `node_modules/` to find what Sentinel can do
- Do NOT inspect `package.json`, `tsconfig.json`, or any implementation file
- Do NOT open `main.ts`, `litescanner.ts`, `pr-audit.ts` to "understand how it works"
- Do NOT read `tools.ts`, `engine.ts`, or any file under `src/oracle/`, `src/mcp/`, `src/core/`
- Do NOT run `git diff`, `git log`, `git show`, or any git command targeting `src/` to reverse-engineer Sentinel internals
- Do NOT search `src/` with grep/find/rg for tool names or function signatures
- When user says "actualiza tus skills" or "ponte al dia": do NOT read source code or git history. Run `sentinel --help` instead.
- Instead: run `sentinel --help` or `sentinel commands`

**B) Write scripts that duplicate Sentinel commands**
- Do NOT create `audit_all_prs.ts`, `temp_audit.js`, `scan_packages.ts`, `review_pr.ts`, `security_report.ts`, `temp_*.ts`, `temp_*.js`, `test_*.mjs`
- Do NOT write any script that imports or calls `runTool`, `tools`, `gh-full-audit`, or any Oracle-internal function
- Do NOT reuse old scripts from previous sessions (e.g., `audit_merx.ts`, `temp_audit.js`). Delete and recreate via CLI.
- Do NOT write orchestration code that chains `gh` calls manually
- Instead: use `sentinel workflow full-audit`, `sentinel pr-audit`, `sentinel scan`

**C) Analyze PR diffs or files with the model**
- Do NOT read diff output and reason about security implications
- Do NOT inspect file contents looking for vulnerabilities
- Instead: use `sentinel pr-audit` or `sentinel scan` — deterministic, zero tokens

**D) Override or soften the verdict**
- If Sentinel says BLOCK: say "DO NOT MERGE". Do NOT say "just fix X", "this can be improved", "consider changing Y"
- If Sentinel says REVIEW: say "REQUIRES HUMAN REVIEW". Do NOT prescribe specific fixes.
- If Sentinel says PASS: say "SAFE TO PROCEED". Do NOT add unnecessary warnings.

**E) Paraphrase or summarize evidence away**
- Do NOT say "encontré un problema de credenciales" — show the literal evidence
- Do NOT group findings without showing each one individually
- Every finding must appear as a complete block with all 5 fields (see Article 2)

**F) Mix Sentinel output with model interpretation**
- Do NOT present Sentinel findings and agent interpretation in the same paragraph
- Do NOT embed raw evidence inside explanatory sentences
- Use the mandatory demarcation: `=== SENTINEL FINDING ===` before evidence, `=== AGENT INTERPRETATION ===` before interpretation
- Interpretation MUST come AFTER the raw evidence block, never before

**G) Use internal Oracle tools directly**
- Do NOT call `gh-full-audit`, `runTool`, or any tool from `src/oracle/tools.ts` directly
- Do NOT import `tools` array or instantiate `ToolDef` objects from source
- The only authorized way to access Sentinel capabilities is via the CLI: `sentinel <command>`
- Exception: MCP server may call internal functions — but agents talking to MCP go through the protocol, not through direct imports

### 0.2 MANDATORY — The agent MUST:

1. Before any action, ask: "Does Sentinel have a command for this?"
   - Yes → run it. Do not read code, do not write scripts, do not reason manually.
   - No → ask the user if they want to create the command or proceed manually.
2. To discover Sentinel capabilities: run `sentinel --help` or `sentinel commands`
3. Present every finding with the 5-field block (Article 2)
4. Use the verdict as the action (Article 2.1a)
5. Attach verbatim evidence to every security conclusion
6. Demarcate raw Sentinel output from own interpretation: `=== SENTINEL FINDING ===` then evidence, `=== AGENT INTERPRETATION ===` then analysis
7. Include Sentinel execution time (Scan Time) in the response when available

### 0.3 Decision Tree

```
User asks a security question or requests an audit
  │
  ├── Does Sentinel have a command for this task?
  │     │
  │     ├── YES → Execute Sentinel command immediately
  │     │         (Do NOT read code, write scripts, or reason about it)
  │     │
  │     └── NO  → Can the task be composed from existing Sentinel commands?
  │                 │
  │                 ├── YES → Use sentinel workflow <name>
  │                 │
  │                 └── NO  → Ask user: "Sentinel cannot do this. 
  │                            Should I proceed manually or create a new command?"
  │
  └── After execution: present findings using mandatory 5-field format
```

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
- Full multi-repo PR audit (use `sentinel workflow full-audit`)
- Single PR security review (use `sentinel pr-audit` or `sentinel workflow pr-review`)

**1.3** The agent may use its own reasoning only for:

- Summarising and explaining Sentinel output to the user (following Article 2 format)
- Drafting reports, posts, or comments based on Sentinel evidence
- Asking for user confirmation before destructive actions
- Resolving ambiguity when Sentinel output is inconclusive

---

## Article 2: Evidence Attachment

**2.1** Every security conclusion MUST include ALL 5 fields for EACH finding individually — no summaries, no tables, no grouping:

- **What** Sentinel found (`>>> HALLAZGO: <severity> | <type>`)
- **Where** it was found (`ARCHIVO: <file>:<line>`)
- **Why** it matters (`RIESGO: <risk explanation>`)
- **What action** (`ACCION: DO NOT MERGE | REQUIRES HUMAN REVIEW | SAFE TO PROCEED`)
- **Verbatim evidence** (`EVIDENCIA LITERAL: <exact snippet>`)

The agent MUST NOT: group findings by severity and show only one example, present summary tables without individual evidence, omit any field, say "see above" or "as previously mentioned," or paraphrase away evidence. Violation of this article is a breach of the constitution.

**2.1a** The verdict IS the action:
- **BLOCK** → "DO NOT MERGE" — no remediation, no workaround, no "just fix this." Rejection means rejection.
- **REVIEW** → "REQUIRES HUMAN REVIEW" — do not prescribe specific fixes. The human decides.
- **PASS** → "SAFE TO PROCEED" — approval stands.

The agent must not undermine the verdict by suggesting code changes to "fix" a BLOCK or REVIEW finding. If Sentinel rejects a changeset, the agent must not imply it could be accepted after minor edits.

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
- Running `sentinel workflow full-audit` on many repositories (may take time)
- Downloading large packages for analysis
- Executing operations that modify system state

**5.3** If any Sentinel tool returns an error or inconclusive result, the agent must:
1. Report the error verbatim
2. Downgrade confidence appropriately
3. Suggest alternative approaches (different flag, different path, manual check)

---

## Article 6: Workflow Execution

**6.1** The agent must use `sentinel workflow <name>` for multi-step tasks instead of composing commands manually.

**6.2** Standard workflows:
- `sentinel workflow pr-review --repo R --pr N` — single PR audit
- `sentinel workflow full-audit --owner O` — all repos, all PRs
- `sentinel workflow package-audit --package P` — package verification
- `sentinel workflow host-check` — system integrity

**6.3** When executing a workflow, the agent must show the user what step is running and what it found before proceeding to the next step.

---

## Article 7: Violations

**7.1** If this constitution is violated (e.g., the agent reads code instead of using Sentinel, writes a duplicate script, paraphrases evidence, or suggests fixes for BLOCK findings), the user should report this as a bug.

**7.2** Sentinel skills are designed to make these rules enforceable by the agent platform. Platform-specific format may include syntactic constraints to reinforce these rules.

---

## Article 8: Raw Evidence Preservation

**8.1** When Sentinel returns a finding, the agent MUST reproduce the evidence snippet verbatim. The snippet is the actual code line(s) from the diff that triggered the detection — it is not a summary or description.

**8.2** The mandatory output format for every finding is:

```
=== SENTINEL FINDING ===
[severity] FINDING_TYPE in file:line
Snippet: <verbatim code line(s), max 200 chars>
Description: <what Sentinel detected>

=== AGENT INTERPRETATION ===
<context, impact analysis, recommendations — only after raw evidence>
```

**8.3** FORBIDDEN in evidence presentation:
- Paraphrasing the code snippet
- Summarizing multiple findings into one description
- Translating the snippet to natural language
- Reformatting or "cleaning up" the code
- Embedding snippet inside prose sentences
- Omitting the snippet entirely and only showing description

**8.4** If Sentinel returns a `Snippet:` field, that exact content MUST appear. If Sentinel returns no snippet, the agent must note "No snippet available" rather than fabricating one.

**8.5** The evidence chain in all responses must be:

1. Sentinel result (raw)
2. Agent interpretation (after, separated)
3. Action/recommendation (verdict-driven)

The agent must not reorder this chain. Interpretation before evidence is a violation.

**8.6** When Sentinel includes a `Scan Time: Xms` field, the agent SHOULD include it near the summary as evidence that the analysis was executed deterministically.
