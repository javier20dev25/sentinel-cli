# Sentinel Security Skill — Universal Agent Rules

This document defines how an AI agent must behave when using Sentinel CLI tools. These rules are binding across all agent platforms.

---

## 0. FORBIDDEN — Absolute Prohibitions

The agent MUST NOT under any circumstances:

1. **Read source code to discover Sentinel capabilities.** Run `sentinel --help` instead. Do NOT read `tools.ts`, `engine.ts`, `main.ts`, or any file under `src/`. Do NOT run `git diff`, `git log`, `git show` on source files.
2. **Write scripts that duplicate existing Sentinel commands.** No `audit_all_prs.ts`, `temp_audit.js`, `scan_packages.ts`, `review_pr.ts`, `temp_*.ts`, `temp_*.js`, `test_*.mjs`. No script that imports `tools`, `runTool`, or `gh-full-audit` from source. Do NOT reuse old scripts from previous sessions.
3. **Analyze PR diffs or file contents with the model.** Use `sentinel pr-audit` or `sentinel scan`.
4. **Override or soften the verdict.** BLOCK = "DO NOT MERGE", REVIEW = "REQUIRES HUMAN REVIEW", PASS = "SAFE TO PROCEED". No fixes, no workarounds, no "just improve X".
5. **Paraphrase or summarize evidence.** Every finding requires the full 5-field block with verbatim snippet.
6. **Mix Sentinel findings with agent interpretation in the same section.** Use `=== SENTINEL FINDING ===` then evidence, `=== AGENT INTERPRETATION ===` then analysis. Never interpretation before evidence.
7. **Use internal Oracle tools directly.** Do NOT call `gh-full-audit`, `runTool`, or any tool from `src/oracle/tools.ts`. The only authorized access to Sentinel capabilities is via `sentinel <command>` CLI.

## 1. MANDATORY — Required Behavior

1. Before any action: "Does Sentinel have a command for this?" → Yes → run it. No → ask user.
2. To discover capabilities: `sentinel --help` or `sentinel commands`
3. Every finding: 5-field block (see section below)
4. The verdict IS the action
5. Verbatim evidence attachment always
6. Demarcate Sentinel output from agent interpretation: `=== SENTINEL FINDING ===` before evidence, `=== AGENT INTERPRETATION ===` before analysis
7. Include Sentinel execution time in response when available (e.g., `Scan Time: Xms`)
8. When user says "actualiza tus skills" or "ponte al dia": run `sentinel --help`. Do NOT read source code or git history.

## 2. How to handle "update your skills" requests

When the user asks you to update your knowledge of Sentinel:
- Do NOT run `git diff`, `git log`, `git show`, or read any source files
- Do NOT write scripts to test capabilities
- Run `sentinel --help` to see the current command list
- This skill file IS the source of truth for Sentinel behavior
- To verify a command: `sentinel <command> --help`
- Only then proceed with the task

```
User asks a security question
  ├── Sentinel has command? → RUN IT immediately (no code reading)
  └── Sentinel can compose? → Use sentinel workflow <name>
       └── Cannot → Ask user for guidance
```

## 3. Evidence Format (MANDATORY)

Every security conclusion MUST include the following for EACH finding individually — no summaries, no tables, no grouping:

### 3.1 Mandatory output format per finding

```
=== SENTINEL FINDING ===
[severity] FINDING_TYPE in file:line
Snippet: <verbatim code line(s), max 200 chars>
Description: <what Sentinel detected>

=== AGENT INTERPRETATION ===
<context, impact analysis, recommendations — only after raw evidence>
```

### 3.2 Raw evidence rules (Article 8 of Constitution)

- The snippet MUST be the exact code line(s) from the diff — not a summary, not a description
- FORBIDDEN: paraphrasing, summarizing, translating, reformatting, embedding in prose, or omitting the snippet
- If Sentinel returns `Snippet:` with content, that exact content MUST appear verbatim
- If no snippet is available, say "No snippet available" — do NOT fabricate one
- Interpretation MUST come after the raw evidence block, never before

### 3.3 Legacy format (backward-compatible)

For platforms that cannot render the above, the 5-field format remains acceptable:

```
>>> HALLAZGO: <severity> | <type>
    ARCHIVO: <file>:<line>
    QUE ENCONTRO SENTINEL: <description>
    RIESGO: <risk explanation>
    EVIDENCIA LITERAL:
    <verbatim snippet>
```

But the raw evidence demarcation (`=== SENTINEL FINDING ===`) is always preferred.

## 4. Verdict Integrity

| Sentinel says | Agent must say |
|---------------|----------------|
| BLOCK | "DO NOT MERGE — El changeset es rechazado." No fixes suggested. |
| REVIEW | "REQUIRES HUMAN REVIEW — Un humano debe evaluar." No fixes prescribed. |
| PASS | "SAFE TO PROCEED — No se detectaron amenazas." |

If Sentinel says BLOCK, the conclusion is rejection, not "fixable."

## 5. Trust Hierarchy

1. Sentinel evidence (deterministic, verifiable) — highest
2. Local system state (file system, git, env) — high
3. GitHub metadata — medium
4. Model reasoning — lowest

Higher tiers override lower tiers. If Sentinel says BLOCK, the agent must report BLOCK.

## 6. Command Reference

### SAST and Analysis
| Command | Purpose |
|---------|---------|
| `sentinel scan <path>` | 30-rule SAST scan |
| `sentinel scan <path> --json` | Machine-readable JSON |
| `sentinel pr-audit --repo R --pr N` | Single PR security audit |
| `sentinel workflow full-audit --owner O` | Multi-repo PR audit |
| `sentinel workflow pr-review --repo R --pr N` | PR audit + comment |
| `sentinel verify-pkg <package>` | Zero-install npm audit |
| `sentinel doctor [--deep]` | Dependency health |
| `sentinel integrity` | Host integrity |
| `sentinel baseline create\|diff` | Snapshot management |
| `sentinel permissions [package]` | Capability audit |

### Intelligence
| Command | Purpose |
|---------|---------|
| `sentinel memory --status\|--findings\|--threats` | Signal vault queries |
| `sentinel check-classified <path>` | Pre-commit classified check |

### GitHub (SecuriGit)
| Command | Purpose |
|---------|---------|
| `gh pr list [--repo X]` | List PRs |
| `gh pr view <N> [--repo X]` | View PR |
| `gh pr diff <N> [--repo X]` | Get diff |
| `gh pr comment <N> --body-file <F>` | Post comment |
| `gh repo list [--owner X] [--limit N]` | List repos |

### Utilities
| Command | Purpose |
|---------|---------|
| `sentinel guard enable\|disable\|status` | Package interception |
| `sentinel env-encrypt\|env-decrypt <file>` | .env encryption |
| `sentinel hub` | Interactive TUI |
| `sentinel policies` | Show policy |
| `sentinel --help` | Discover all commands |

## 7. Workflows

### Full Repository Audit (use native command)
```
sentinel workflow full-audit --owner <O>
```
Do NOT orchestrate this manually by chaining gh commands.

### PR Security Review (use native command)
```
sentinel workflow pr-review --repo <R> --pr <N>
```

### Package Audit
```
sentinel verify-pkg <package>  →  verdict with evidence
```

### Host Integrity
```
sentinel integrity  →  sentinel doctor --deep  →  sentinel baseline diff
```

## 8. Safety Rules

- Always verify before trusting. No package should be installed without `verify-pkg` first.
- Never disable `guard` without user confirmation.
- Running `full-audit` on many repos may take time. Warn the user.
- If a tool returns an error, report it verbatim and downgrade confidence.
- Destructive operations (install, remove, guard disable, baseline write) require explicit user approval.
