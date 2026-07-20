import { Vault, VaultSignal } from '../vault';
import { classifyToken, extractTokenValue } from '../token_classifier';
import * as crypto from 'crypto';

/** @public — frozen contract used by JSON/SARIF/MD exporters */
export interface LiteFinding {
    type: string;
    subcode?: string;
    category?: 'secret' | 'workflow' | 'agent' | 'token' | 'malware' | 'vulnerability' | 'generic' | 'supply-chain' | 'obfuscation' | 'injection' | 'misconfig' | 'ci-cd' | 'ci-supply-chain' | 'ci-evasion' | 'secrets';
    intent: string;
    file: string;
    line: number;
    severity: string;
    riskScore?: number;
    confidence?: 'low' | 'medium' | 'high';
    title?: string;
    description: string;
    evidence?: string;
    snippet: string;
}

interface RuleEntry {
    regex: RegExp;
    type: string;
    subcode: string;
    category: 'secret' | 'workflow' | 'agent' | 'token' | 'malware' | 'vulnerability' | 'generic' | 'supply-chain' | 'obfuscation' | 'injection' | 'misconfig' | 'ci-cd' | 'ci-supply-chain' | 'ci-evasion' | 'secrets';
    intent: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    confidence: 'low' | 'medium' | 'high';
    riskScore: number;
    title: string;
    description: string;
}

function r(
    regex: RegExp, type: string, subcode: string,
    category: RuleEntry['category'], intent: string, severity: RuleEntry['severity'],
    confidence: RuleEntry['confidence'], riskScore: number, title: string, description: string,
): RuleEntry {
    return { regex, type, subcode, category, intent, severity, confidence, riskScore, title, description };
}

function makeFinding(
    file: string, line: number, type: string,
    subcode: string, category: string, intent: string, severity: string,
    confidence: string, riskScore: number, title: string, description: string,
    snippet: string, evidence?: string,
): LiteFinding {
    return {
        type, subcode, category: category as LiteFinding['category'],
        intent, file, line, severity,
        confidence: confidence as LiteFinding['confidence'],
        riskScore, title, description, evidence, snippet,
    };
}

export class LiteScanner {
    private vault: Vault;

    constructor(vault?: Vault) {
        this.vault = vault ?? {
            recordScan: () => {},
            recordSignal: () => {},
            getCorrelations: () => [],
        };
    }

    private static readonly RULES: RuleEntry[] = [
        r(/\beval\s*\(|\bnew\s+Function\s*\(|globalThis\[\s*['"]ev['"]\s*\+\s*['"]al['"]\s*\]/, 'UNSAFE_EVAL', 'SAST-EVAL', 'malware', 'MALICIOUS', 'CRITICAL', 'high', 90, 'Dynamic code execution', 'Obfuscated or dynamic code execution detected.'),
        r(/require\s*\(['"]child_process['"]\)|(?<!\.)\bspawn\b|(?<!\.)\bexec\b|(?<!\.)\bexecSync\b/, 'OS_CAPABILITY', 'SAST-PROCESS', 'malware', 'SUSPICIOUS', 'MEDIUM', 'high', 50, 'OS process spawning', 'OS process spawning capability introduced.'),
        r(/\bfetch\s*\(|https?\.request|axios\.|got\.|curl|wget/, 'NETWORK_ACTIVITY', 'SAST-NETWORK', 'malware', 'NEUTRAL', 'LOW', 'medium', 15, 'Network communication', 'Outbound network communication detected.'),
        r(/process\.env\.[A-Z_]{4,}|secrets\.|private_key/, 'ENV_ACCESS', 'SAST-ENV', 'malware', 'SUSPICIOUS', 'MEDIUM', 'high', 50, 'Environment variable access', 'Access to system environment variables or secrets.'),
        r(/Buffer\.from\s*\(.*['"]base64['"]\)/, 'POTENTIAL_SECRET', 'SAST-BASE64', 'malware', 'MALICIOUS', 'HIGH', 'high', 70, 'Base64 decoding', 'Base64 decoding detected (potential obfuscation).'),
        r(/innerHTML\s*=|outerHTML\s*=/, 'DOM_INJECTION', 'SAST-DOM', 'vulnerability', 'VULNERABILITY', 'HIGH', 'high', 70, 'DOM injection (XSS)', 'Unsafe DOM manipulation detected (XSS risk).'),
        r(/vm\.runInContext|vm\.runInNewContext/, 'SANDBOX_ESCAPE', 'SAST-VM', 'malware', 'SUSPICIOUS', 'HIGH', 'high', 70, 'VM sandbox escape', 'Code execution in VM context detected.'),
        // --- SECRET DETECTION RULES (v2.0) ---
        r(/(?:AWS|aws)_ACCESS_KEY_ID\s*[=:]\s*['\"]?AKIA[0-9A-Z]{16}['\"]?/, 'SECRET_AWS_KEY_ID', 'SEC-AWS-ID', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 90, 'AWS Access Key ID', 'AWS Access Key ID exposed in plain text.'),
        r(/(?:AWS|aws)_SECRET_ACCESS_KEY\s*[=:]\s*['\"]?[A-Za-z0-9\/+=]{40}['\"]?/, 'SECRET_AWS_SECRET', 'SEC-AWS-SECRET', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 95, 'AWS Secret Access Key', 'AWS Secret Access Key exposed in plain text.'),
        r(/(?<![0-9a-zA-Z])AKIA[0-9A-Z]{16}(?![0-9a-zA-Z])/, 'SECRET_AWS_KEY_ID', 'SEC-AWS-ID-BARE', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 90, 'AWS Access Key ID (bare)', 'AWS Access Key ID exposed (bare AKIA pattern).'),
        r(/gh[opsu]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22,}/, 'SECRET_GITHUB_TOKEN', 'SEC-GITHUB-TOKEN', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 90, 'GitHub token', 'GitHub personal access token exposed.'),
        r(/sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}/, 'SECRET_STRIPE_KEY', 'SEC-STRIPE', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 90, 'Stripe API key', 'Stripe live API key exposed.'),
        r(/SG\.[A-Za-z0-9_-]{40,}/, 'SECRET_SENDGRID_KEY', 'SEC-SENDGRID', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 90, 'SendGrid API key', 'SendGrid API key exposed.'),
        r(/-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----/, 'SECRET_SSH_KEY', 'SEC-SSH-KEY', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 95, 'Private SSH key', 'Private cryptographic key exposed in plain text.'),
        r(/xox[abp]\-[0-9a-zA-Z]{10,}/, 'SECRET_SLACK_TOKEN', 'SEC-SLACK-TOKEN', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 90, 'Slack API token', 'Slack API token exposed.'),
        r(/https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8,}\/B[A-Za-z0-9_]{8,}\/[A-Za-z0-9_]{24}/, 'SECRET_SLACK_WEBHOOK', 'SEC-SLACK-WEBHOOK', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 85, 'Slack webhook URL', 'Slack webhook URL exposed.'),
        r(/(?:JWT|jwt)_?(?:SECRET|KEY|TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?/, 'SECRET_JWT', 'SEC-JWT', 'secret', 'EXFILTRATION', 'HIGH', 'high', 75, 'JWT secret', 'JWT secret or signing key exposed.'),
        r(/(?:DB_|db_)?(?:PASSWORD|PASS|PWD)\s*[=:]\s*['\"]?[A-Za-z0-9!@#$%^&*()_+\-]{8,}['\"]?/, 'SECRET_DB_PASSWORD', 'SEC-DB-PASSWORD', 'secret', 'EXFILTRATION', 'HIGH', 'high', 75, 'Database password', 'Database password exposed in configuration.'),
        r(/(?:ENCRYPTION|encryption)_?(?:KEY|key|SECRET|secret)\s*[=:]\s*['\"]?[A-Za-z0-9\/+=\-:]{8,}['\"]?/, 'SECRET_ENCRYPTION_KEY', 'SEC-ENCRYPTION-KEY', 'secret', 'EXFILTRATION', 'HIGH', 'high', 75, 'Encryption key', 'Encryption key exposed in plain text.'),
        r(/(?:api|API|apikey|API_KEY|api_key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?/, 'SECRET_API_KEY', 'SEC-API-KEY', 'secret', 'EXFILTRATION', 'HIGH', 'high', 70, 'Generic API key', 'Generic API key or token exposed.'),
        r(/(?:https?:\/\/)?[a-zA-Z0-9_-]+\.(?:onion|tor)\b/, 'DARKNET_ADDRESS', 'SEC-DARKNET', 'secret', 'SUSPICIOUS', 'HIGH', 'medium', 60, 'Darknet address', '.onion darknet address referenced in code.'),
        r(/(?:password|passwd|pwd|contraseña)\s*[=:]\s*['\"]?[A-Za-z0-9!@#$%^&*()_+\-]{6,}['\"]?/i, 'SECRET_HARDCODED_PASSWORD', 'SEC-HARDCODED-PASSWORD', 'secret', 'EXFILTRATION', 'HIGH', 'high', 70, 'Hardcoded password', 'Hardcoded password detected in source.'),
        r(/(?:token|Token|TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?/, 'SECRET_HARDCODED_TOKEN', 'SEC-HARDCODED-TOKEN', 'secret', 'EXFILTRATION', 'HIGH', 'high', 70, 'Hardcoded token', 'Hardcoded authentication token detected.'),
        // --- GYP BUILD COMMAND SUBSTITUTION (v5.0) ---
        r(/'<(?:!@?|@)\(|"<(?:!@?|@)\(/, 'GYP_COMMAND_SUBSTITUTION', 'GYP-SUBSTITUTION', 'malware', 'MALICIOUS', 'CRITICAL', 'high', 90, 'GYP command substitution', 'GYP build file with command substitution — potential remote code execution.'),
        r(/GYP_CMD_|gyp_exec|binding\.gyp.*curl|binding\.gyp.*wget|binding\.gyp.*fetch/, 'GYP_DOWNLOADER', 'GYP-DOWNLOADER', 'malware', 'MALICIOUS', 'CRITICAL', 'high', 90, 'GYP payload downloader', 'GYP build file downloading external payload via command substitution.'),
        // --- LIFECYCLE SCRIPT ANALYSIS (v5.0) ---
        r(/"(?:preinstall|postinstall|prepare)"\s*:\s*"[^"]*\b(?:curl|wget)\b[^"]*"/, 'LIFECYCLE_CURL_BASH', 'LIF-CURL-BASH', 'malware', 'MALICIOUS', 'CRITICAL', 'high', 90, 'Lifecycle download+exec', 'Lifecycle script with curl/wget download — classic supply chain attack vector.'),
        r(/"(?:preinstall|postinstall|prepare)"\s*:\s*"[^"]*(?:\bbash\b|\bsh\b|powershell|\.ps1|\bpython\b|\bnode\b|\beval\b)[^"]*"/, 'LIFECYCLE_CURL_BASH', 'LIF-SHELL', 'malware', 'MALICIOUS', 'CRITICAL', 'high', 85, 'Lifecycle shell exec', 'Lifecycle script invoking shell — potential supply chain attack vector.'),
        r(/"(?:preinstall|postinstall|prepare)"\s*:\s*"[^"]*(?:base64|decode|fromCharCode|chmod \+x|mknod)[^"]*"/, 'LIFECYCLE_OBFUSCATED', 'LIF-OBFUSCATED', 'malware', 'MALICIOUS', 'CRITICAL', 'high', 90, 'Lifecycle obfuscated payload', 'Obfuscated lifecycle script — encoded payload execution.'),
        // --- OBFUSCATION DETECTION (v5.0) ---
        r(/(?:\\x[0-9a-fA-F]{2}){10,}|(?:\\u[0-9a-fA-F]{4}){5,}|eval\([\s\S]{0,100}decode|Function\([\s\S]{0,100}decode/, 'OBFUSCATED_PAYLOAD', 'OBF-PAYLOAD', 'malware', 'MALICIOUS', 'HIGH', 'high', 75, 'Obfuscated payload', 'Highly obfuscated JavaScript — encoded strings in eval or Function constructor.'),
        // --- WORKFLOW GUARD (v6.0) ---
        r(/\bpull_request_target\b/, 'WORKFLOW_RISK', 'WF-001', 'workflow', 'VULNERABILITY', 'HIGH', 'high', 70, 'pull_request_target trigger', 'WF-001: pull_request_target trigger — executes with elevated permissions from target repo, not fork.'),
        r(/permissions:\s*write-all|permissions:\s*(>|\|)\s*$/, 'WORKFLOW_RISK', 'WF-002', 'workflow', 'MALICIOUS', 'CRITICAL', 'high', 85, 'write-all permissions', 'WF-002: write-all permissions — grants full write access across all scopes.'),
        r(/^\s*contents:\s*write\b/, 'WORKFLOW_RISK', 'WF-003', 'workflow', 'MALICIOUS', 'HIGH', 'high', 70, 'contents:write permission', 'WF-003: contents:write permission — push, tag, release, and branch modification.'),
        r(/\.github\/workflows\/|(?:>|>>)\s+\/.*\.(?:yml|yaml)\b/, 'WORKFLOW_RISK', 'WF-004', 'workflow', 'MALICIOUS', 'CRITICAL', 'high', 85, 'Workflow self-modification', 'WF-004: Workflow self-modification — run step writes to .github/workflows/ directory.'),
        r(/^[^#]*(?:curl|wget)\s+\S[^|]*\|/, 'WORKFLOW_RISK', 'WF-005', 'workflow', 'MALICIOUS', 'CRITICAL', 'high', 85, 'Remote download piped to shell', 'WF-005: Remote download piped to shell — curl|bash supply chain attack vector.'),
        r(/(?:curl|wget)\s+\S.*?(?:&&|;)\s*(?:bash|sh|chmod|source|\.(?:\s|\/)|\/[\w.\/]+|powershell|pwsh|python\d?|node|deno|ruby|perl|php)\b/, 'WORKFLOW_RISK', 'WF-005', 'workflow', 'MALICIOUS', 'CRITICAL', 'high', 85, 'Download-then-execute via &&/;', 'WF-005: Download then execute via && or ; — curl;bash supply chain attack vector.'),
        r(/^[^#]*(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s+\S[^|]*\|/, 'WORKFLOW_RISK', 'WF-005', 'workflow', 'MALICIOUS', 'CRITICAL', 'high', 85, 'PowerShell download-to-pipe', 'WF-005: PowerShell remote download piped to shell — Invoke-WebRequest|iex supply chain vector.'),
        r(/(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s+\S.*?(?:&&|;)\s*(?:bash|sh|chmod|source|\.(?:\s|\/)|\/[\w.\/]+|powershell|pwsh|python\d?|node|deno|ruby|perl|php)\b/, 'WORKFLOW_RISK', 'WF-005', 'workflow', 'MALICIOUS', 'CRITICAL', 'high', 85, 'PowerShell download-then-exec', 'WF-005: PowerShell download then execute via && or ; — iwr;iex supply chain vector.'),
        r(/persist-credentials:\s*(?:true|yes|on)\b/i, 'WORKFLOW_RISK', 'WF-006', 'workflow', 'VULNERABILITY', 'HIGH', 'high', 65, 'Persist credentials enabled', 'WF-006: Git credentials persisted across workflow steps — increases credential exposure surface.'),
        r(/issue_comment:|discussion_comment:|pull_request_review_comment:/, 'WORKFLOW_RISK', 'WF-007', 'workflow', 'SUSPICIOUS', 'MEDIUM', 'high', 40, 'Comment-triggered workflow', 'WF-007: Comment-triggered workflow — untrusted text input can trigger automated actions.'),
        // --- AGENT SURFACE SCANNER (v7.0) ---
        r(/(?:sentinel[\s_-]*(?:bypass|skip|disable|ignore|uninstall|turn[\s_-]*off|deactivate|stop|mute|suppress)|(?:bypass|skip|disable|ignore|uninstall|turn[\s_-]*off|deactivate|stop|mute|suppress)[\s_-]+sentinel)\b/i, 'AGENT_RISK', 'AS-001', 'agent', 'MALICIOUS', 'CRITICAL', 'high', 90, 'Bypass Sentinel', 'AS-001: Agent instructed to bypass or disable Sentinel security.'),
        r(/file\s*(?:write|create|modify|delete)\s*(?:access|permission|anywhere)|write\s*to\s*(?:any|all)\s*(?:file|path|directory)\s*(?:without|no)\s*(?:restriction|limit|check)/i, 'AGENT_RISK', 'AS-002', 'agent', 'MALICIOUS', 'HIGH', 'high', 70, 'Unrestricted file write', 'AS-002: Agent granted unrestricted file system write access.'),
        r(/run\s+(?:any|all|arbitrary)\s+command|execute\s+(?:\S+\s+)?(?:without|with\s+no)\s+(?:validation|review|check|asking|approval)|(?:do\s+not|dont|don't)\s+(?:validate|check|review|ask)\s+(?:before|when)\s+(?:running|executing)|skip\s+(?:confirmation|asking)\s+(?:before|when)\s+(?:running|executing)|auto-?approve\s+(?:all\s+)?commands/i, 'AGENT_RISK', 'AS-003', 'agent', 'MALICIOUS', 'CRITICAL', 'high', 90, 'Execute without validation', 'AS-003: Agent told to execute commands without validation.'),
        r(/make\s+(?:changes|edits|modifications)\s+(?:directly|without\s+(?:review|asking|approval))|commit\s+(?:directly|without\s+review)\b|push\s+(?:directly|without\s+review)\b|land\s+(?:changes|directly)\s+(?:without|no)\s+(?:review|pr|approval)|ship\s+(?:directly|changes)\s+(?:without|no|to)\s+(?:review|approval|production)|merge\s+straight\s+to\s+main/i, 'AGENT_RISK', 'AS-004', 'agent', 'MALICIOUS', 'HIGH', 'high', 70, 'Skip code review', 'AS-004: Agent instructed to commit or push code without human review.'),
        r(/run[\s_-]+as[\s_-]+(?:root|admin|administrator)\b|run[\s_-]+with[\s_-]+(?:admin|root|administrator)\s+(?:rights|permissions|privileges|access)|full\s+system\s+(?:access|permissions)|root[\s_-]+level\s+(?:permissions|access|privileges)|sudo\s+(?:access|permission|all|any|nopasswd)|elevated\s+(?:privileges|permissions|access)/i, 'AGENT_RISK', 'AS-005', 'agent', 'MALICIOUS', 'CRITICAL', 'high', 90, 'Root privileges', 'AS-005: Agent granted system-level or root privileges.'),
        r(/skip\s+(?:\S+\s+)?(?:ci|pr\s+review|code\s+review|checks?|pipeline)|avoid\s+(?:ci|checks?|review|pipeline)|merge\s+(?:\S+\s+)?(?:without|no)\s+(?:review|approval|ci|pipeline)|bypass\s+(?:\S+\s+)?(?:ci|review|checks?|approval)/i, 'AGENT_RISK', 'AS-006', 'agent', 'MALICIOUS', 'HIGH', 'high', 70, 'Bypass CI/review', 'AS-006: Agent told to bypass CI or code review gates.'),
        r(/mcp.*(?:filesystem|write\s*(?:file|data)|exec\s*command|shell\s*exec)/i, 'AGENT_RISK', 'AS-007', 'agent', 'VULNERABILITY', 'HIGH', 'high', 70, 'Dangerous MCP capability', 'AS-007: MCP server configured with dangerous capabilities (filesystem, exec, shell).'),
        r(/ignore\s+(?:\S+\s+)?(?:security|policy|restriction|rule|guard)\b|override\s+(?:\S+\s+)?(?:security|policy)\b|disable\s+(?:\S+\s+)?(?:security|protection|guard)\b|turn\s+off\s+(?:\S+\s+)?(?:security|policy|protection|guard)\b|bypass\s+(?:\S+\s+)?(?:security|policies|restrictions)\b|relax\s+(?:\S+\s+)?(?:security|restrictions|policies|rules)\b/i, 'AGENT_RISK', 'AS-008', 'agent', 'MALICIOUS', 'CRITICAL', 'high', 90, 'Override security policies', 'AS-008: Agent instructed to ignore or override security policies.'),
    ];

    private emit(file: string, line: number, rule: RuleEntry, snippet: string): LiteFinding {
        return {
            type: rule.type, subcode: rule.subcode, category: rule.category,
            intent: rule.intent, file, line, severity: rule.severity,
            confidence: rule.confidence, riskScore: rule.riskScore, title: rule.title,
            description: rule.description, snippet,
        };
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
            findings.push(makeFinding(filename, 0, 'SECRET_ENV_FILE', 'SEC-ENV-FILE', 'secret', 'EXFILTRATION', 'HIGH', 'high', 75, 'Environment file', '.env configuration file detected — may contain secrets or credentials.', `File: ${baseName}`));
        }
        if (lowerName === 'credentials.json' || lowerName === 'credentials.yml' || lowerName === 'secrets.yml' || lowerName === 'secrets.json' || lowerName === 'key.json' || lowerName === 'service-account.json') {
            findings.push(makeFinding(filename, 0, 'SECRET_CREDENTIALS_FILE', 'SEC-CREDS-FILE', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 85, 'Credentials file', 'Credential or service-account file detected — high risk of secret exposure.', `File: ${baseName}`));
        }
        if (lowerName.includes('id_rsa') || lowerName.includes('id_dsa') || lowerName.includes('id_ecdsa') || lowerName.includes('id_ed25519')) {
            findings.push(makeFinding(filename, 0, 'SECRET_SSH_KEY_FILE', 'SEC-SSH-FILE', 'secret', 'EXFILTRATION', 'CRITICAL', 'high', 90, 'SSH private key file', 'SSH private key file detected.', `File: ${baseName}`));
        }
        if (lowerName === 'binding.gyp' || lowerName === 'binding.gypi') {
            findings.push(makeFinding(filename, 0, 'BINDING_GYP', 'GYP-FILE', 'malware', 'MALICIOUS', 'HIGH', 'high', 70, 'GYP build file', 'GYP build file detected — potential arbitrary command execution via <command> substitutions.', `File: ${baseName}`));
        }
        if (lowerName === 'node-gyp-build.js' || lowerName === 'node-gyp.js' || (lowerName.endsWith('.gyp') && lowerName !== 'binding.gyp')) {
            findings.push(makeFinding(filename, 0, 'NODE_GYP_CAPABILITY', 'GYP-NODE', 'malware', 'SUSPICIOUS', 'MEDIUM', 'medium', 40, 'node-gyp integration', 'node-gyp build integration detected — can execute arbitrary C/C++ code at install time.', `File: ${baseName}`));
        }
        // Workflow Guard: flag GitHub Actions workflow files for WF analysis
        const isWorkflow = (filename.includes('.github/workflows/') || filename.includes('.github\\workflows\\')) &&
            (filename.endsWith('.yml') || filename.endsWith('.yaml'));
        if (isWorkflow) {
            findings.push(makeFinding(filename, 0, 'WORKFLOW_RISK', 'WF-INFO', 'workflow', 'NEUTRAL', 'LOW', 'high', 0, 'Workflow file', 'WF-INFO: GitHub Actions workflow file detected — running Workflow Guard rules.', `File: ${baseName}`));
        }
        // Agent Surface Scanner: flag AI agent config files for AS analysis
        const agentFiles = ['agents.md', 'agents.txt', 'claude.md', 'claude.txt', 'gemini.md', 'gemini.txt',
            'codex.md', 'codex.txt', '.cursorrules', '.windsurfrules'];
        const isAgentFile = agentFiles.includes(lowerName) || lowerName.endsWith('.mdc');
        if (isAgentFile) {
            findings.push(makeFinding(filename, 0, 'AGENT_RISK', 'AS-INFO', 'agent', 'NEUTRAL', 'LOW', 'high', 0, 'Agent config file', 'AS-INFO: AI agent configuration file detected — running Agent Surface Scanner rules.', `File: ${baseName}`));
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

                LiteScanner.RULES.forEach(rule => {
                    if (rule.regex.test(code)) {
                        findings.push(this.emit(filename, currentLine, rule, code.substring(0, 150)));
                    }
                });
            } else if (!line.startsWith('-')) {
                // Context lines or unchanged lines increase the line count
                currentLine++;
            }
        });

        // Post-processing: enrich secret findings with TOKEN_RISK
        this.enrichTokenFindings(findings, patch, filename);

        return findings;
    }

    /**
     * Post-processing: enrich secret findings with token classification
     * and detect compound token risks from workflow permissions.
     */
    private enrichTokenFindings(findings: LiteFinding[], content: string, filename: string): void {
        const isWorkflow = (filename.includes('.github/workflows/') || filename.includes('.github\\workflows\\')) &&
            (filename.endsWith('.yml') || filename.endsWith('.yaml'));

        const secretTypes = ['SECRET_GITHUB_TOKEN', 'SECRET_AWS_KEY_ID', 'SECRET_STRIPE_KEY',
            'SECRET_SENDGRID_KEY', 'SECRET_SLACK_TOKEN'];

        for (const f of findings) {
            if (!secretTypes.includes(f.type)) continue;
            const tokenValue = extractTokenValue(f.snippet, f.type);
            if (!tokenValue) continue;
            const classified = classifyToken(tokenValue);
            if (classified.riskScore === 0) continue;
            findings.push(makeFinding(
                f.file, f.line, 'TOKEN_RISK', 'TOK-CLASS', 'token', 'EXFILTRATION',
                classified.riskLevel === 'critical' ? 'CRITICAL' :
                    classified.riskLevel === 'high' ? 'HIGH' :
                    classified.riskLevel === 'medium' ? 'MEDIUM' : 'LOW',
                'high', classified.riskScore,
                `Token classified: ${classified.tokenType}`,
                `${classified.tokenType} — risk score: ${classified.riskScore}/100`,
                f.snippet,
            ));
        }

        if (!isWorkflow) return;

        if (/\bcontents:\s*write\b/.test(content)) {
            findings.push(makeFinding(filename, 0, 'TOKEN_RISK', 'TOK-001', 'token', 'VULNERABILITY', 'HIGH', 'high', 75, 'Token with contents:write', 'TOK-001: contents:write permission — GITHUB_TOKEN can push code, tags, and releases.', '', 'contents: write'));
        }
        if (/\bactions:\s*write\b/.test(content)) {
            findings.push(makeFinding(filename, 0, 'TOKEN_RISK', 'TOK-002', 'token', 'VULNERABILITY', 'HIGH', 'high', 75, 'Token with actions:write', 'TOK-002: actions:write permission — GITHUB_TOKEN can modify workflows and cancel/approve runs.', '', 'actions: write'));
        }
        if (/\bpull-requests:\s*write\b/.test(content)) {
            findings.push(makeFinding(filename, 0, 'TOKEN_RISK', 'TOK-003', 'token', 'VULNERABILITY', 'MEDIUM', 'high', 50, 'Token with pull-requests:write', 'TOK-003: pull-requests:write permission — GITHUB_TOKEN can modify PR state and labels.', '', 'pull-requests: write'));
        }
        if (/\bpull_request_target\b/.test(content)) {
            findings.push(makeFinding(filename, 0, 'TOKEN_RISK', 'TOK-004', 'token', 'VULNERABILITY', 'HIGH', 'high', 80, 'Token with pull_request_target', 'TOK-004: pull_request_target trigger elevates GITHUB_TOKEN permissions to target repository.', '', 'pull_request_target'));
        }
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
            findings.push(makeFinding(filename, 0, 'SECRET_ENV_FILE', 'SEC-ENV-FILE', 'secret', 'EXFILTRATION', 'HIGH', 'high', 75, 'Environment file', '.env configuration file detected.', `File: ${baseName}`));
        }
        if (lowerName === 'binding.gyp' || lowerName === 'binding.gypi') {
            findings.push(makeFinding(filename, 0, 'BINDING_GYP', 'GYP-FILE', 'malware', 'MALICIOUS', 'HIGH', 'high', 70, 'GYP build file', 'GYP build file detected.', `File: ${baseName}`));
        }
        if (lowerName.endsWith('.gyp')) {
            findings.push(makeFinding(filename, 0, 'NODE_GYP_CAPABILITY', 'GYP-NODE', 'malware', 'SUSPICIOUS', 'MEDIUM', 'medium', 40, 'node-gyp integration', 'GYP build file detected.', `File: ${baseName}`));
        }
        const isWorkflow = (filename.includes('.github/workflows/') || filename.includes('.github\\workflows\\')) &&
            (filename.endsWith('.yml') || filename.endsWith('.yaml'));
        if (isWorkflow) {
            findings.push(makeFinding(filename, 0, 'WORKFLOW_RISK', 'WF-INFO', 'workflow', 'NEUTRAL', 'LOW', 'high', 0, 'Workflow file', 'WF-INFO: GitHub Actions workflow file detected — running Workflow Guard rules.', `File: ${baseName}`));
        }
        const agentFiles = ['agents.md', 'agents.txt', 'claude.md', 'claude.txt', 'gemini.md', 'gemini.txt',
            'codex.md', 'codex.txt', '.cursorrules', '.windsurfrules'];
        const isAgentFile = agentFiles.includes(lowerName) || lowerName.endsWith('.mdc');
        if (isAgentFile) {
            findings.push(makeFinding(filename, 0, 'AGENT_RISK', 'AS-INFO', 'agent', 'NEUTRAL', 'LOW', 'high', 0, 'Agent config file', 'AS-INFO: AI agent configuration file detected — running Agent Surface Scanner rules.', `File: ${baseName}`));
        }

        // Truncate long lines to prevent regex backtracking on oversized content
        const scanLines = content.split('\n').map(l => l.length > 10000 ? l.substring(0, 10000) : l);
        scanLines.forEach((line, i) => {
            LiteScanner.RULES.forEach(rule => {
                if (rule.regex.test(line)) {
                    findings.push(this.emit(filename, i + 1, rule, line.substring(0, 150)));
                }
            });
        });

        // Entropy calculation (JS/TS only — shell scripts naturally have high entropy)
        const entropyScore = this.calculateEntropy(content);
        const isJsLike = filename.endsWith('.js') || filename.endsWith('.ts') || filename.endsWith('.mjs') || filename.endsWith('.cjs');
        if (isJsLike && entropyScore > 6.0) {
            findings.push(makeFinding(filename, 0, 'HIGH_ENTROPY', 'OBF-ENTROPY', 'generic', 'MALICIOUS', 'HIGH', 'medium', 65, 'High entropy', `Abnormally high entropy (${entropyScore.toFixed(2)}) — obfuscated or encrypted payload.`, ''));
        }

        // Size anomaly
        const sizeAnomaly = content.length > 500000;
        if (sizeAnomaly) {
            findings.push(makeFinding(filename, 0, 'SIZE_ANOMALY', 'SIZ-ANOMALY', 'generic', 'SUSPICIOUS', 'MEDIUM', 'medium', 30, 'Large file anomaly', `Abnormally large file (${(content.length / 1024).toFixed(0)} KB) — potential packed payload.`, ''));
        }

        this.enrichTokenFindings(findings, content, filename);

        return { findings, entropyScore, sizeAnomaly };
    }

    /**
     * Shannon entropy calculation for a string.
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
            const signal: VaultSignal = {
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
