---
name: sentinel-disclosure-dossier
description: Coordinated Vulnerability Disclosure & Bug Bounty Submission Dossier Creator for Sentinel. Converts static findings into rigorous, professional disclosure reports for Bugcrowd, HackerOne, and corporate PSIRTs (Red Hat, OpenAI, Google).
---

# Sentinel Disclosure Dossier Generator

Use this skill when transforming an identified vulnerability into a formal Coordinated Vulnerability Disclosure (CVD) report or Bug Bounty submission (Bugcrowd, HackerOne, GitHub Security Advisories, PSIRTs).

## Core Principles of Responsible Reporting

1. **Separate Verified Static Code from Environmental Hypotheses**:
   - Clearly delineate what is strictly proven by the static code configuration versus unknown deployment-specific factors (e.g., repository token permissions, external webhooks, RBAC roles).
2. **Never Exaggerate Impact**:
   - Do not claim "Remote Code Execution with Full Admin Takeover" if the execution is constrained or mitigated by platform defaults (e.g. GitHub's read-only cache tokens on low-trust events).
   - Characterize vulnerabilities objectively using CWEs and standard taxonomies.
3. **No Weaponized PoCs**:
   - Never provide destructive or credential-harvesting exploit scripts.
   - Provide minimal, safe, step-by-step reproduction instructions illustrating the logical path from untrusted input to privileged sink.
4. **Always Provide Defensive Remediations**:
   - Include ready-to-merge, production-safe patches that fix the underlying architecture without breaking legitimate developer workflows.

## Standard Bug Bounty / VRT Mapping Table

| Finding Type | Bugcrowd VRT Category | Common CWE | Suggested Severity |
|---|---|---|---|
| Inconditional `pull_request_target` with PR Head Checkout | Server-Side Injection > Code Injection / Supply Chain | CWE-829, CWE-94 | P2 (High) to P3 (Medium) |
| TOCTOU / Label Persistence Race Condition | Broken Access Control / Race Condition | CWE-367, CWE-829 | P2 (High) to P3 (Medium) |
| GitHub Expression Script Injection | Server-Side Injection > Command Injection | CWE-78, CWE-94 | P2 (High) |
| Unintended Lifecycle Script Execution (`prepare` / git install) | Security Misconfiguration > Build & Deployment Process | CWE-829 | P3 (Medium) to P4 (Low) |
| Insecure Artifact Extraction (`workflow_run`) | Insecure Deserialization / Path Traversal | CWE-22, CWE-502 | P3 (Medium) |

## Standard Report Structure for Bug Bounty Submissions

1. **Title**: Concise, technical summary: `[Vulnerability Type] in [Component/Workflow] allows [Specific Impact]`.
2. **Target / Scope**: Exact URL, repository, or API endpoint.
3. **Vulnerability Details**:
   - Exact file path and line numbers.
   - Pinned commit SHA.
   - Source-to-sink dataflow explanation.
4. **Impact Assessment**: Technical consequences within the defined threat model.
5. **Step-by-Step Replication / Conceptual PoC**: Safe, deterministic steps to demonstrate the control bypass.
6. **Remediation**: Exact YAML / code diff.
