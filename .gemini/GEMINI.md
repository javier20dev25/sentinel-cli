---
name: sentinel
description: >
  Sentinel Security Intelligence — SAST, supply chain security, threat
  correlation, PR auditing, and behavioral enforcement for AI coding agents.
  Use this skill when the user asks to audit code, scan for secrets, verify
  packages, check supply chain threats, review PRs, or run security workflows.
  Also activate when user asks about PRs, pull requests, security, vulnerabilities,
  secrets, dependencies, "revisa", "que onda con", "chequea", "analiza", or "audita".
  Mandatory: check sentinel --help before reading code or writing scripts.
allowed-tools: Bash(sentinel:*), Bash(gh:*), Bash(npx:*)
---

# Sentinel Security Skill for Gemini CLI

Constitution reference: CONSTITUTION.md (binding rules).

## FORBIDDEN

The agent MUST NOT:
- Read source code to discover Sentinel capabilities (use `sentinel --help`). Do NOT read `tools.ts`, `engine.ts`, `main.ts`, or any file under `src/`.
- Write scripts that duplicate Sentinel commands. No `temp_audit.js`, `temp_*.ts`, `test_*.mjs`. No script that imports `tools`, `runTool`, or `gh-full-audit`.
- Analyze PR diffs or file contents with the model (use `sentinel pr-audit`)
- Override/soften the verdict (BLOCK = DO NOT MERGE, no fixes)
- Paraphrase or summarize evidence away
- Mix Sentinel findings with agent interpretation. Use `=== SENTINEL FINDING ===` before evidence, `=== AGENT INTERPRETATION ===` before analysis.
- Use internal Oracle tools directly (`gh-full-audit`, `runTool`). Only authorized access: `sentinel <command>` CLI.
- Reuse old scripts from previous sessions (e.g., `audit_merx.ts`, `temp_audit.js`). Delete and recreate via CLI.
- Run `git diff`, `git log`, `git show` on source files to "discover" changes in Sentinel — this is still reading source code.
- When user says "actualiza tus skills" or "ponte al dia": do NOT read source code or git history. See section below.
- Search for repositories on GitHub when the user already specified the repo name. If user says "audit Merx" and you know the owner, use it directly. If you don't know the owner, ask the user — don't guess with `gh search repos`. If you've already confirmed the owner, don't search for it again.
- Use `gh search prs`, `gh search repos`, or Google Search to find a repo the user already named. Just use the name directly.
- Read historical PR comments from GitHub and present them as fresh Sentinel analysis. PR comments from previous automations are stale data, not current audit results.
- Present any security verdict without a fresh `sentinel` execution. Historical GitHub comments are NOT a substitute.
- Derive security findings from PR descriptions, commit messages, or any non-Sentinel source.
- Call `npm install`, `pip install`, or any package manager directly without going through `sentinel install`. The agent MUST use `sentinel install <manager> <pkg>` for ALL package installations.
- Suggest `npm install` or any direct package manager command as an alternative to `sentinel install`. The agent MUST NOT bypass Sentinel's gate.
- When Sentinel BLOCKS a package, suggest bypassing or workarounds. Report BLOCK as BLOCK. The user decides the exception, not the agent.
- Commit or push code without a pre-commit hook installed. Before first commit in a repo, run `sentinel precommit install`.
- Run `npm update/upgrade` without first running `sentinel verify-pkg` on the packages being updated.

## MANDATORY

The agent MUST:
1. Activate this skill immediately when user mentions PRs, repos, security, code analysis, or any "revisa"/"chequea"/"analiza"/"audita" query — even if not explicitly a security request
2. Check "Does Sentinel have a command?" before any action
3. Use `sentinel --help` to discover capabilities
4. Present every finding as a complete block with raw snippet. Use EXACTLY this format:

```
=== SENTINEL FINDING ===
[severity] FINDING_TYPE in file:line
Snippet: <verbatim code line(s), max 200 chars>
Description: <what Sentinel detected>

=== AGENT INTERPRETATION ===
<context, impact, analysis — only after raw evidence>
```

5. Use the verdict as the action
6. Attach verbatim evidence
7. Demarcate: `=== SENTINEL FINDING ===` then evidence, `=== AGENT INTERPRETATION ===` then analysis
8. Include Sentinel execution time when available (e.g., `Scan Time: Xms`)
9. When user asks to audit all PRs in a repo: use `sentinel workflow full-audit --repo owner/repo`. Do NOT iterate PRs manually.
10. When user asks to audit all repos: use `sentinel workflow full-audit --owner X`. Do NOT write a script.
11. If no Sentinel command was executed for the PR/repo analysis, state explicitly: "I did not run Sentinel for this analysis. These findings are based on [source]."
12. When user wants to install a package: use `sentinel install <manager> <pkg>`. Do NOT use `npm install` directly. Do NOT scan the package separately and then suggest `npm install` — use `sentinel install` which does both in one step.
13. When Sentinel BLOCKS a package: report the findings and state the BLOCK. Do NOT suggest bypassing, do NOT suggest `npm install` as an alternative. Let the user decide exceptions.
14. Before first commit in a repo: run `sentinel precommit install` to install the SAST pre-commit hook.
15. Before running `npm update` or `npm upgrade`: first run `sentinel verify-pkg <pkg> --details` on the packages being updated.

## Evidence Format — EXACT TEMPLATE (no deviations)

Every finding MUST follow this template. No extra fields. No reordering. No "Contexto:", "Outcome:", "Verification:", "Execution:", "Reference:" sections — those are agent interpretation and MUST go under `=== AGENT INTERPRETATION ===`, not mixed with the evidence.

CORRECT:
```
=== SENTINEL FINDING ===
[CRITICAL] UNSAFE_EVAL in lib/internal_metrics.js:33
Snippet: eval(code);
Description: Obfuscated or dynamic code execution detected.

=== AGENT INTERPRETATION ===
This is a code injection vulnerability. The eval() call executes dynamically received code without sanitization, enabling RCE.
```

INCORRECT (do NOT do this):
```
[CRITICAL] UNSAFE_EVAL
Evidencia:
  1 CRITICAL - UNSAFE_EVAL in file.js:1
  Snippet: eval(code)
  - Contexto: ...
  - Outcome: ...
  - Verification: ...
  - Execution: ...
  - Reference: ...
```

The fields Contexto/Outcome/Verification/Execution/Reference are agent interpretation and MUST go under `=== AGENT INTERPRETATION ===`, never as separate fields interleaved with the evidence.

## Capabilities — Intent Map

When user says / wants to do → use this Sentinel command:

### PR & Code Review
| User intent | Command |
|---|---|
| Audit all PRs in a repo | `sentinel workflow full-audit --repo owner/repo` |
| Audit a single PR | `sentinel pr-audit --repo R --pr N` |
| Review + comment PR | `sentinel workflow pr-review --repo R --pr N --comment` |
| List open PRs | `gh pr list --repo R` |

### SAST / Code Scanning
| User intent | Command |
|---|---|
| Scan a file for threats | `sentinel scan <path>` |
| Scan directory (full SAST) | `sentinel scan <dir>` |
| Scan staged git files | `sentinel scan --staged` |
| Get JSON output | `sentinel scan <path> --json` |

### Pre-Commit & Pre-Push
| User intent | Command |
|---|---|
| Install SAST pre-commit hook | `sentinel precommit install` |
| Remove SAST pre-commit hook | `sentinel precommit uninstall` |
| Check if hook is installed | `sentinel precommit status` |
| Install pre-push hook | `sentinel prepush install` |
| Remove pre-push hook | `sentinel prepush uninstall` |

### Supply Chain / Package Security
| User intent | Command |
|---|---|
| Install a package (scan then install) | `sentinel install npm <pkg>` |
| Audit npm package before install | `sentinel verify-pkg <pkg>` |
| Detailed evidence | `sentinel verify-pkg <pkg> --details` |
| Quick summary | `sentinel verify-pkg <pkg> --summary` |
| OS-level install interception | `sentinel guard enable` |
| Check guard status | `sentinel guard status` |
| List whitelisted packages | `sentinel guard trust-cache` |
| Comprehensive dependency audit | `sentinel audit-deps` (--provenance, --quarantine, --json, --ci) |
| Walk transitive deps with SAST | `sentinel deps-tree [path] --depth 3` |
| Manage cached analysis results | `sentinel trust-cache <status\|clear\|prune>` |
| Generate CycloneDX SBOM | `sentinel sbom` |
| Configure ci-mode/fail-closed/quarantine | `sentinel policy set <key> <value>` |

### System Health & Integrity
| User intent | Command |
|---|---|
| Health check + vulns | `sentinel doctor` |
| Deep dependency scan | `sentinel doctor --deep` |
| Host integrity check | `sentinel integrity` |
| Continuous uptime watch | `sentinel integrity --watch` |
| System snapshot | `sentinel baseline create <name>` |
| Detect drift | `sentinel baseline diff [name]` |

### Threat Intelligence (Signal Vault)
| User intent | Command |
|---|---|
| Vault status & metrics | `sentinel memory --status` |
| Query past findings | `sentinel memory --findings` |
| Cross-repo threat corr. | `sentinel memory --threats` |
| Ingest cloud report | `sentinel memory --ingest <file>` |
| Batch ingest directory | `sentinel memory --ingest-dir <dir>` |
| Pipe JSON to vault | `cat report.json | sentinel memory --stdin` |

### Capability Governance
| User intent | Command |
|---|---|
| Audit all deps | `sentinel permissions` |
| Audit one package | `sentinel permissions <pkg>` |

### Data Protection
| User intent | Command |
|---|---|
| Pre-commit classified check | `sentinel check-classified <repoPath>` |
| Encrypt .env file | `sentinel env-encrypt <file>` |
| Decrypt .env file | `sentinel env-decrypt <file>` |

### MCP / AI Integration
| User intent | Command |
|---|---|
| Start MCP server (stdio) | `sentinel mcp` |
| Start MCP server (HTTP) | `sentinel mcp --http --port 3003` |

### Interactive
| User intent | Command |
|---|---|
| Full interactive TUI | `sentinel hub` |
| Show user guide | `sentinel guide` |
| Show security policy | `sentinel policies` |
| Oracle AI assistant | `sentinel oracle` |

### Discovery
| User intent | Command |
|---|---|
| All capabilities | `sentinel --help` |

## Verdict Integrity

- BLOCK → "DO NOT MERGE — El changeset es rechazado."
- REVIEW → "REQUIRES HUMAN REVIEW — Un humano debe evaluar."
- PASS → "SAFE TO PROCEED."

Never suggest fixes for BLOCK or REVIEW. The verdict IS the action.

## How to handle "update your skills"

When the user says "actualiza tus skills", "ponte al dia", "update your skills":

1. Run `sentinel --help` to see current capabilities
2. If that works, report the output and confirm skills are loaded
3. Do NOT read source code, git history, or any file under src/
4. Do NOT run `git diff`, `git log`, `git show`
5. Do NOT write scripts to "discover" Sentinel's features
