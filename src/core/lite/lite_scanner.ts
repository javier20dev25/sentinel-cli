/**
 * Sentinel Lite Engine (v2.0)
 * 
 * "Intentionally Degraded" version of the Oracle Engine for CLI distribution.
 * Provides high-utility local scanning while protecting proprietary Reasoning IP.
 * 
 * v2.0 adds SECRET_DETECTION rules for credential exfiltration.
 */

import { SignalVault, ScanSignal } from '../../cli/intelligence/signal_vault';
import * as crypto from 'crypto';

export interface LiteFinding {
    type: string;
    intent: string;
    file: string;
    line: number;
    severity: string;
    description: string;
    snippet: string;
}

export class LiteScanner {
    private vault: SignalVault;

    private static readonly RULES = [
        { regex: /\beval\s*\(|\bnew\s+Function\s*\(|globalThis\[\s*['"]ev['"]\s*\+\s*['"]al['"]\s*\]/, type: 'UNSAFE_EVAL',          intent: 'MALICIOUS', severity: 'CRITICAL', description: 'Obfuscated or dynamic code execution detected.' },
        { regex: /require\s*\(['"]child_process['"]\)|(?<!\.)\bspawn\b|(?<!\.)\bexec\b|(?<!\.)\bexecSync\b/, type: 'OS_CAPABILITY', intent: 'SUSPICIOUS', severity: 'MEDIUM', description: 'OS process spawning capability introduced.' },
        { regex: /\bfetch\s*\(|https?\.request|axios\.|got\.|curl|wget/,                  type: 'NETWORK_ACTIVITY',     intent: 'NEUTRAL',    severity: 'LOW',    description: 'Outbound network communication detected.' },
        { regex: /process\.env\.[A-Z_]{4,}|secrets\.|private_key/,                      type: 'ENV_ACCESS',           intent: 'SUSPICIOUS', severity: 'MEDIUM', description: 'Access to system environment variables or secrets.' },
        { regex: /Buffer\.from\s*\(.*['"]base64['"]\)/,                                 type: 'POTENTIAL_SECRET',     intent: 'MALICIOUS',  severity: 'HIGH',   description: 'Base64 decoding detected (potential obfuscation).' },
        { regex: /innerHTML\s*=|outerHTML\s*=/,                                         type: 'DOM_INJECTION',        intent: 'VULNERABILITY', severity: 'HIGH',   description: 'Unsafe DOM manipulation detected (XSS risk).' },
        { regex: /vm\.runInContext|vm\.runInNewContext/,                                type: 'SANDBOX_ESCAPE',       intent: 'SUSPICIOUS', severity: 'HIGH',   description: 'Code execution in VM context detected.' },
        // --- SECRET DETECTION RULES (v2.0) ---
        { regex: /(?:AWS|aws)_ACCESS_KEY_ID\s*[=:]\s*['\"]?AKIA[0-9A-Z]{16}['\"]?/,                type: 'SECRET_AWS_KEY_ID',    intent: 'EXFILTRATION', severity: 'CRITICAL', description: 'AWS Access Key ID exposed in plain text.' },
        { regex: /(?:AWS|aws)_SECRET_ACCESS_KEY\s*[=:]\s*['\"]?[A-Za-z0-9\/+=]{40}['\"]?/,         type: 'SECRET_AWS_SECRET',    intent: 'EXFILTRATION', severity: 'CRITICAL', description: 'AWS Secret Access Key exposed in plain text.' },
        { regex: /(?<![0-9a-zA-Z])AKIA[0-9A-Z]{16}(?![0-9a-zA-Z])/,                              type: 'SECRET_AWS_KEY_ID',    intent: 'EXFILTRATION', severity: 'CRITICAL', description: 'AWS Access Key ID exposed (bare AKIA pattern).' },
        { regex: /gh[opsu]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22,}/, type: 'SECRET_GITHUB_TOKEN', intent: 'EXFILTRATION', severity: 'CRITICAL', description: 'GitHub personal access token exposed.' },
        { regex: /sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}/,                  type: 'SECRET_STRIPE_KEY',    intent: 'EXFILTRATION', severity: 'CRITICAL', description: 'Stripe live API key exposed.' },
        { regex: /SG\.[A-Za-z0-9_-]{40,}/,                                                type: 'SECRET_SENDGRID_KEY',  intent: 'EXFILTRATION', severity: 'CRITICAL', description: 'SendGrid API key exposed.' },
        { regex: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----/,        type: 'SECRET_SSH_KEY',       intent: 'EXFILTRATION', severity: 'CRITICAL', description: 'Private cryptographic key exposed in plain text.' },
        { regex: /xox[abp]\-[0-9a-zA-Z]{10,}/,                                          type: 'SECRET_SLACK_TOKEN',   intent: 'EXFILTRATION', severity: 'CRITICAL', description: 'Slack API token exposed.' },
        { regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8,}\/B[A-Za-z0-9_]{8,}\/[A-Za-z0-9_]{24}/, type: 'SECRET_SLACK_WEBHOOK', intent: 'EXFILTRATION', severity: 'CRITICAL', description: 'Slack webhook URL exposed.' },
        { regex: /(?:JWT|jwt)_?(?:SECRET|KEY|TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?/, type: 'SECRET_JWT', intent: 'EXFILTRATION', severity: 'HIGH', description: 'JWT secret or signing key exposed.' },
        { regex: /(?:DB_|db_)?(?:PASSWORD|PASS|PWD)\s*[=:]\s*['\"]?[A-Za-z0-9!@#$%^&*()_+\-]{8,}['\"]?/, type: 'SECRET_DB_PASSWORD', intent: 'EXFILTRATION', severity: 'HIGH', description: 'Database password exposed in configuration.' },
        { regex: /(?:ENCRYPTION|encryption)_?(?:KEY|key|SECRET|secret)\s*[=:]\s*['\"]?[A-Za-z0-9\/+=\-:]{8,}['\"]?/, type: 'SECRET_ENCRYPTION_KEY', intent: 'EXFILTRATION', severity: 'HIGH', description: 'Encryption key exposed in plain text.' },
        { regex: /(?:api|API|apikey|API_KEY|api_key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?/, type: 'SECRET_API_KEY', intent: 'EXFILTRATION', severity: 'HIGH', description: 'Generic API key or token exposed.' },
        { regex: /(?:https?:\/\/)?[a-zA-Z0-9_-]+\.(?:onion|tor)\b/,                      type: 'DARKNET_ADDRESS',     intent: 'SUSPICIOUS', severity: 'HIGH', description: '.onion darknet address referenced in code.' },
        { regex: /(?:password|passwd|pwd|contraseña)\s*[=:]\s*['\"]?[A-Za-z0-9!@#$%^&*()_+\-]{6,}['\"]?/i, type: 'SECRET_HARDCODED_PASSWORD', intent: 'EXFILTRATION', severity: 'HIGH', description: 'Hardcoded password detected in source.' },
        { regex: /(?:token|Token|TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?/,       type: 'SECRET_HARDCODED_TOKEN', intent: 'EXFILTRATION', severity: 'HIGH', description: 'Hardcoded authentication token detected.' },
        // --- GYP BUILD COMMAND SUBSTITUTION (v5.0) ---
        { regex: /'<(?:!@?|@)\(|"<(?:!@?|@)\(/, type: 'GYP_COMMAND_SUBSTITUTION', intent: 'MALICIOUS', severity: 'CRITICAL', description: 'GYP build file with command substitution — potential remote code execution.' },
        { regex: /GYP_CMD_|gyp_exec|binding\.gyp.*curl|binding\.gyp.*wget|binding\.gyp.*fetch/, type: 'GYP_DOWNLOADER', intent: 'MALICIOUS', severity: 'CRITICAL', description: 'GYP build file downloading external payload via command substitution.' },
        // --- LIFECYCLE SCRIPT ANALYSIS (v5.0) ---
        { regex: /"(?:preinstall|postinstall|prepare)"\s*:\s*"[^"]*\b(?:curl|wget)\b[^"]*"/, type: 'LIFECYCLE_CURL_BASH', intent: 'MALICIOUS', severity: 'CRITICAL', description: 'Lifecycle script with curl/wget download — classic supply chain attack vector.' },
        { regex: /"(?:preinstall|postinstall|prepare)"\s*:\s*"[^"]*(?:\bbash\b|\bsh\b|powershell|\.ps1|\bpython\b|\bnode\b|\beval\b)[^"]*"/, type: 'LIFECYCLE_CURL_BASH', intent: 'MALICIOUS', severity: 'CRITICAL', description: 'Lifecycle script invoking shell — potential supply chain attack vector.' },
        { regex: /"(?:preinstall|postinstall|prepare)"\s*:\s*"[^"]*(?:base64|decode|fromCharCode|chmod \+x|mknod)[^"]*"/, type: 'LIFECYCLE_OBFUSCATED', intent: 'MALICIOUS', severity: 'CRITICAL', description: 'Obfuscated lifecycle script — encoded payload execution.' },
        // --- OBFUSCATION DETECTION (v5.0) ---
        { regex: /(?:\\x[0-9a-fA-F]{2}){10,}|(?:\\u[0-9a-fA-F]{4}){5,}|eval\([\s\S]{0,100}decode|Function\([\s\S]{0,100}decode/, type: 'OBFUSCATED_PAYLOAD', intent: 'MALICIOUS', severity: 'HIGH', description: 'Highly obfuscated JavaScript — encoded strings in eval or Function constructor.' },
    ];

    constructor() {
        this.vault = new SignalVault();
    }

    /**
     * Performs a local scan of a file patch.
     * Uses the same deterministic SAST rules as the Pro version.
     */
    public scanPatch(filename: string, patch: string): LiteFinding[] {
        const findings: LiteFinding[] = [];
        const lines = patch.split('\n');
        let currentLine = 0;

        // --- Filename-based detection ---
        const baseName = filename.split(/[/\\]/).pop() || filename;
        const lowerName = baseName.toLowerCase();
        if (lowerName === '.env' || lowerName.startsWith('.env.') || lowerName === '.env.example') {
            findings.push({
                file: filename, line: 0, type: 'SECRET_ENV_FILE',
                intent: 'EXFILTRATION', severity: 'HIGH',
                description: '.env configuration file detected — may contain secrets or credentials.',
                snippet: `File: ${baseName}`
            });
        }
        if (lowerName === 'credentials.json' || lowerName === 'credentials.yml' || lowerName === 'secrets.yml' || lowerName === 'secrets.json' || lowerName === 'key.json' || lowerName === 'service-account.json') {
            findings.push({
                file: filename, line: 0, type: 'SECRET_CREDENTIALS_FILE',
                intent: 'EXFILTRATION', severity: 'CRITICAL',
                description: 'Credential or service-account file detected — high risk of secret exposure.',
                snippet: `File: ${baseName}`
            });
        }
        if (lowerName.includes('id_rsa') || lowerName.includes('id_dsa') || lowerName.includes('id_ecdsa') || lowerName.includes('id_ed25519')) {
            findings.push({
                file: filename, line: 0, type: 'SECRET_SSH_KEY_FILE',
                intent: 'EXFILTRATION', severity: 'CRITICAL',
                description: 'SSH private key file detected.',
                snippet: `File: ${baseName}`
            });
        }
        if (lowerName === 'binding.gyp' || lowerName === 'binding.gypi') {
            findings.push({
                file: filename, line: 0, type: 'BINDING_GYP',
                intent: 'MALICIOUS', severity: 'HIGH',
                description: 'GYP build file detected — potential arbitrary command execution via <command> substitutions.',
                snippet: `File: ${baseName}`
            });
        }
        if (lowerName === 'node-gyp-build.js' || lowerName === 'node-gyp.js' || (lowerName.endsWith('.gyp') && lowerName !== 'binding.gyp')) {
            findings.push({
                file: filename, line: 0, type: 'NODE_GYP_CAPABILITY',
                intent: 'SUSPICIOUS', severity: 'MEDIUM',
                description: 'node-gyp build integration detected — can execute arbitrary C/C++ code at install time.',
                snippet: `File: ${baseName}`
            });
        }

        lines.forEach(line => {
            if (line.startsWith('@@')) {
                // Parse chunk header: @@ -line,count +line,count @@
                const match = line.match(/\+(\d+)/);
                if (match) currentLine = parseInt(match[1]) - 1;
                return;
            }

            if (line.startsWith('+') && !line.startsWith('+++')) {
                currentLine++;
                const code = line.substring(1).trim();
                if (!code) return;

                LiteScanner.RULES.forEach(r => {
                    if (r.regex.test(code)) {
                        findings.push({
                            file: filename,
                            line: currentLine,
                            type: r.type,
                            intent: r.intent,
                            severity: r.severity,
                            description: r.description,
                            snippet: code.substring(0, 150)
                        });
                    }
                });
            } else if (!line.startsWith('-')) {
                // Context lines or unchanged lines increase the line count
                currentLine++;
            }
        });

        return findings;
    }

    /**
     * Full file content scan (not diff-based).
     * Scans all lines, calculates entropy, flags size anomalies.
     */
    public scanFileContent(filename: string, content: string): { findings: LiteFinding[]; entropyScore: number; sizeAnomaly: boolean } {
        const findings: LiteFinding[] = [];
        const baseName = filename.split(/[/\\]/).pop() || filename;
        const lowerName = baseName.toLowerCase();

        // Reuse filename-based detection
        if (lowerName === '.env' || lowerName.startsWith('.env.') || lowerName === '.env.example') {
            findings.push({ file: filename, line: 0, type: 'SECRET_ENV_FILE', intent: 'EXFILTRATION', severity: 'HIGH', description: '.env configuration file detected.', snippet: `File: ${baseName}` });
        }
        if (lowerName === 'binding.gyp' || lowerName === 'binding.gypi') {
            findings.push({ file: filename, line: 0, type: 'BINDING_GYP', intent: 'MALICIOUS', severity: 'HIGH', description: 'GYP build file detected.', snippet: `File: ${baseName}` });
        }
        if (lowerName.endsWith('.gyp')) {
            findings.push({ file: filename, line: 0, type: 'NODE_GYP_CAPABILITY', intent: 'SUSPICIOUS', severity: 'MEDIUM', description: 'GYP build file detected.', snippet: `File: ${baseName}` });
        }

        // Truncate long lines to prevent regex backtracking on oversized content
        const scanLines = content.split('\n').map(l => l.length > 10000 ? l.substring(0, 10000) : l);
        scanLines.forEach((line, i) => {
            LiteScanner.RULES.forEach(r => {
                if (r.regex.test(line)) {
                    findings.push({
                        file: filename, line: i + 1, type: r.type,
                        intent: r.intent, severity: r.severity,
                        description: r.description,
                        snippet: line.substring(0, 150)
                    });
                }
            });
        });

        // Entropy calculation (JS/TS only — shell scripts naturally have high entropy)
        const entropyScore = this.calculateEntropy(content);
        const isJsLike = filename.endsWith('.js') || filename.endsWith('.ts') || filename.endsWith('.mjs') || filename.endsWith('.cjs');
        if (isJsLike && entropyScore > 6.0) {
            findings.push({
                file: filename, line: 0, type: 'HIGH_ENTROPY',
                intent: 'MALICIOUS', severity: 'HIGH',
                description: `Abnormally high entropy (${entropyScore.toFixed(2)}) — obfuscated or encrypted payload.`,
                snippet: ''
            });
        }

        // Size anomaly
        const sizeAnomaly = content.length > 500000;
        if (sizeAnomaly) {
            findings.push({
                file: filename, line: 0, type: 'SIZE_ANOMALY',
                intent: 'SUSPICIOUS', severity: 'MEDIUM',
                description: `Abnormally large file (${(content.length / 1024).toFixed(0)} KB) — potential packed payload.`,
                snippet: ''
            });
        }

        return { findings, entropyScore, sizeAnomaly };
    }

    /**
     * Shannon entropy calculation for a string.
     * Values > 5.5 suggest obfuscated/encrypted content.
     */
    private calculateEntropy(content: string): number {
        const len = content.length;
        if (len === 0) return 0;
        const freq: Record<number, number> = {};
        const sample = content.substring(0, 100000);
        const sampleLen = sample.length;
        for (let i = 0; i < sampleLen; i++) {
            const byte = sample.charCodeAt(i);
            freq[byte] = (freq[byte] || 0) + 1;
        }
        let entropy = 0;
        for (const count of Object.values(freq)) {
            const p = count / sampleLen;
            if (p > 0) entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    /**
     * Orchestrates the local scan, persists signals to the Vault,
     * and performs basic temporal correlation.
     */
    public async auditPR(repo: string, pr: number, author: string, files: { filename: string, patch: string }[]) {
        const scanId = crypto.randomBytes(8).toString('hex');
        const allFindings: LiteFinding[] = [];

        for (const file of files) {
            const findings = this.scanPatch(file.filename, file.patch);
            allFindings.push(...findings);
        }

        // 1. Persist scan metadata first (signals have FK to scans)
        this.vault.recordScan({
            id: scanId,
            repo,
            pr,
            author,
            score: allFindings.some(f => f.severity === 'CRITICAL') ? 90 :
                   allFindings.some(f => f.severity === 'HIGH') ? 60 : 10,
            band: allFindings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' :
                  allFindings.some(f => f.severity === 'HIGH') ? 'SUSPICIOUS' : 'SAFE',
        });

        // 2. Persist signals to local Vault
        for (const f of allFindings) {
            const signal: ScanSignal = {
                repo,
                author,
                signal_type: f.type,
                weight: f.severity === 'CRITICAL' ? 1.0 : (f.severity === 'HIGH' ? 0.7 : 0.3),
                file_path: f.file,
                source_scan: scanId
            };
            this.vault.recordSignal(signal);
        }

        // 3. Perform Temporal Correlation (Local Drift)
        const currentTypes = Array.from(new Set(allFindings.map(f => f.type)));
        const historicalCorrelations = this.vault.getCorrelations(author, currentTypes);

        // 4. Local Verdict Logic
        let riskBand = 'SAFE';
        let decision = 'PASS';
        if (allFindings.some(f => f.severity === 'CRITICAL')) {
            riskBand = 'CRITICAL';
            decision = 'BLOCK';
        } else if (allFindings.some(f => f.severity === 'HIGH') || historicalCorrelations.length > 2) {
            riskBand = 'SUSPICIOUS';
            decision = 'REVIEW';
        }

        return {
            scanId,
            findings: allFindings,
            correlations: historicalCorrelations,
            verdict: {
                band: riskBand,
                decision,
                correlationCount: historicalCorrelations.length
            },
            cta: decision !== 'PASS' ? "View advanced causal audit on Sentinel Cloud" : null
        };
    }
}
