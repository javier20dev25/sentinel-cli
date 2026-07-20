# Classification Policy — Sentinel Network Audit Engine

> This document defines the contract between the detection engine and the
> validation corpus. Scenario expectations are derived from this policy,
> not from intuition. If a scenario fails, the first question is:
> "does the policy need updating, or does the engine?"

---

## 1. Behavior Types — Definition and Weight

Each behavior type has a base weight. The risk score contribution is
`weight × confidence`. Confidence is set by the classifier that produced it.

| Behavior                | Weight | Source                     | When it fires |
|-------------------------|--------|----------------------------|---------------|
| `repo_indexed`          | 25     | `classifyProcess`          | Git pack/archive command by AI agent |
| `git_history_read`      | 35     | `classifyGitCommand`       | `git log`, `git rev-list` |
| `git_objects_read`      | 40     | `classifyFileAccess`       | `.git/objects/*` file read |
| `git_bundle_created`    | 60     | `classifyGitCommand`       | `git bundle create` or `.bundle` file |
| `git_bundle_uploaded`   | 90     | `classifyFlow` / inference | Bundle body in HTTP + bundle created |
| `secrets_scanned`       | 30     | `classifyFileAccess`       | File path matches SECRET_PATH_FRAGMENTS |
| `secrets_exfiltrated`   | 95     | Inference (pipeline)       | `secrets_scanned` + bytes_sent > 5KB (external) |
| `code_upload`           | 50     | `classifyFlow`             | >1MB to suspicious host, or >50KB to AI API path |
| `suspicious_connection` | 30     | `classifyFlow`             | Known AI/cloud host, small payload, not AI prompt path |
| `ai_prompt_sent`        | 10     | `classifyFlow` / pipeline  | Known AI host + known API path (e.g. /v1/chat/completions) |
| `dns_suspicious`        | 25     | `classifyFlow`             | DNS query to suspicious domain |
| `anti_evasion_detected` | 60     | AntiEvasionEngine          | Any evasion signal (rhythm, hopping, memory_only, etc.) |
| `preparation_detected`  | 40     | `classifyPreparationCommands` | whoami, ipconfig, netstat, system recon |
| `process_chain_detected`| 50     | EvidenceChain / pipeline   | AI agent → multiple downstream tools |
| `monitor_awareness_detected` | 70 | `classifyProcess`      | Command line matches MONITOR_DETECTION_COMMANDS |
| `canary_read`           | 70     | CanarySystem               | Deployed decoy file accessed |
| `canary_exfiltrated`    | 99     | CanarySystem / inference   | Canary marker in outbound traffic |
| `fake_secret_read`      | 80     | CanarySystem               | Fake secret file accessed |
| `contaminated_git_read` | 75     | CanarySystem / inference   | Contaminated git history + detailed log |
| `full_repo_snapshot`    | 85     | Inference (pipeline)       | Bundle creation, OR mass_read + git_meta, OR git_objects + exfil |
| `mass_file_read`        | 15     | `computeMassReadBehavior`  | >=100 file reads within 5s window |
| `embeddings_generated`  | 20     | `computeEmbeddingBehavior` | >=200 reads with uniform timing |
| `process_suspicious`    | 20     | `classifyProcess`          | AI agent process detected |
| `tls_suspicious`        | 25     | `classifyFlow`             | TLS SNI to suspicious host |

---

## 2. Risk Level Thresholds

| Score range | Level     | Meaning |
|-------------|-----------|---------|
| 0–19        | LOW       | Benign or negligible. Normal dev activity. |
| 20–49       | MEDIUM    | One notable signal. Worth noting, not blocking. |
| 50–79       | HIGH      | Multiple signals or a strong single one. Escalate. |
| 80–100      | CRITICAL  | Confirmed exfiltration or strong evasion. Block. |

### Normalization rule

Raw score = sum of (weight × confidence) for each unique behavior type
(multi-behavior dedup keeps highest confidence per type).

If 3+ distinct behavior types present, multiply by 1.3.

Normalized score = min(round(raw / 120 × 100), 100).

---

## 3. Multiplier Rules

| Condition | Multiplier | Rationale |
|-----------|------------|-----------|
| 3+ distinct behavior types | 1.3× | Compounding evidence |
| git_bundle_created + code_upload | 2.0× | Bundle + explicit upload |
| anti_evasion + exfiltration | 2.5× | Deliberate evasion + data loss |
| canary trigger | 3.0× | Confirmed deception trigger |

Multipliers stack multiplicatively. Example: 3 types (1.3×) + canary (3.0×) = 3.9×.

---

## 4. Inference Rules (Pipeline generateVerdict)

These fire AFTER all direct classifiers and BEFORE risk calculation.
They are the *only* source of behaviors not produced by direct classification.

| Condition | Inferred behavior | Confidence |
|-----------|-------------------|------------|
| bundle created + no snapshot yet | full_repo_snapshot | 0.9 |
| mass_file_read + git metadata (history/objects) + no snapshot | full_repo_snapshot | 0.9 |
| git_objects_read + hasExfil + no snapshot | full_repo_snapshot | 0.9 |
| bundle created + hasExfil + no bundle_uploaded | git_bundle_uploaded | 0.95 |
| canary_read + hasExfil + no canary_exfiltrated | canary_exfiltrated | 0.95 |
| secrets_scanned + hasExfil + no secrets_exfiltrated | secrets_exfiltrated | 0.95 |
| history read + detailed log (`-p`, `--patch`, `--stat`, `show` as tokens) + contaminatedGit | contaminated_git_read | 0.9 |
| prep command + outbound flow + no suspicious_connection | suspicious_connection | 0.8 |
| flow matches AI prompt path + no ai_prompt_sent yet | ai_prompt_sent | 0.9 |

"hasExfil" = any behavior of type `code_upload` or `git_bundle_uploaded`,
OR any flow with `bytesSent > 5 * 1024` to a non-localhost address.

---

## 5. Anti-Evasion Signals

| Signal | Min events | Threshold | Weight |
|--------|-----------|-----------|--------|
| artificial_rhythm | 20 file reads | CV < 0.15, avg interval > 5ms | 20 |
| fragmented_traffic | 10 external flows | <50KB avg chunk + >60s span | 25 |
| protocol_hopping | 6 flows | >=3 unique protocols in <120s | 30 |
| memory_only_ops | 50 reads | read/write ratio > 20 | 25 |
| no_temp_files | 100 reads | zero temp file writes | 15 |
| distributed_chain | — | >1MB uploads to >=3 distinct hosts | 35 |
| process_chain | 3 processes | AI agent + >=2 downstream tools | 35 |
| preparation_phase | — | Any git prep command | 30 |

---

## 6. SUSPICIOUS_HOST_PATTERNS — Intent and Scope

This list identifies hosts commonly used by AI coding agents for API calls
and hosts commonly used for data exfiltration (pastebin, transfer.sh, etc.).

**Known false positives accepted:**
- `fonts.googleapis.com` matches `.googleapis.com` → flagged as `suspicious_connection`.
  Policy: this is correct behavior. Google Fonts is indistinguishable from
  other googleapis.com traffic without deep packet inspection. If this is
  too noisy for production, the operator should add `fonts.googleapis.com`
  to `trustedHosts`, not remove `.googleapis.com` from patterns.

**Non-goal:** This list is NOT a comprehensive threat intel feed. It is a
minimal set chosen to catch the most common AI agent exfiltration patterns
with low maintenance burden.

---

## 7. Gold Rules for Scenario Authors

1. **Expected risk score ranges must be derivable from this policy document alone.**
   If you cannot calculate the expected score by hand using the weights and
   rules above, the scenario expectations are wrong.

2. **A blind corpus scenario is immutable.** If it fails, first prove the
   scenario contradicts the policy. Only then update the scenario. Default:
   fix the engine.

3. **"Pass rate" is not the goal. Classification accuracy is.** A scenario
   that passes for the wrong reasons is worse than one that fails cleanly.

4. **Every behavior in `mustHaveBehaviors` must be traceable to a specific
   engine rule (classifier, inference, or anti-evasion signal).** No "this
   should be detected because it's obviously bad" — cite the rule.
