"use strict";
/**
 * Sentinel Capability Analyzer (v1.0)
 *
 * Maps low-level findings to high-level 'Capabilities' for Governance.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.CapabilityAnalyzer = void 0;
class CapabilityAnalyzer {
    /**
     * Maps findings from a scan to high-level capabilities.
     */
    static analyze(findings) {
        const capabilities = new Map();
        findings.forEach(f => {
            let cap = null;
            switch (f.type) {
                case 'NETWORK_ACTIVITY':
                    cap = 'NETWORK';
                    break;
                case 'OS_CAPABILITY':
                    cap = 'PROCESS_EXEC';
                    break;
                case 'ENV_ACCESS':
                    cap = 'ENV_ACCESS';
                    break;
                case 'UNSAFE_EVAL':
                    cap = 'DYNAMIC_EXEC';
                    break;
                case 'DOM_INJECTION':
                    cap = 'DOM_MANIPULATION';
                    break;
                case 'SANDBOX_ESCAPE':
                    cap = 'PROCESS_EXEC';
                    break;
                // Secret detection rules → all map to CREDENTIAL_LEAK
                case 'SECRET_ENV_FILE':
                case 'SECRET_CREDENTIALS_FILE':
                case 'SECRET_SSH_KEY_FILE':
                case 'SECRET_AWS_KEY_ID':
                case 'SECRET_AWS_SECRET':
                case 'SECRET_GITHUB_TOKEN':
                case 'SECRET_STRIPE_KEY':
                case 'SECRET_SENDGRID_KEY':
                case 'SECRET_SSH_KEY':
                case 'SECRET_SLACK_TOKEN':
                case 'SECRET_JWT':
                case 'SECRET_DB_PASSWORD':
                case 'SECRET_ENCRYPTION_KEY':
                case 'SECRET_API_KEY':
                case 'SECRET_HARDCODED_PASSWORD':
                case 'SECRET_HARDCODED_TOKEN':
                    cap = 'CREDENTIAL_LEAK';
                    break;
            }
            if (cap) {
                const existing = capabilities.get(cap);
                // Escalate risk if intent is MALICIOUS
                let riskLevel = f.severity;
                if (f.intent === 'MALICIOUS')
                    riskLevel = 'CRITICAL';
                if (f.intent === 'VULNERABILITY' && riskLevel === 'CRITICAL')
                    riskLevel = 'HIGH'; // Downgrade "accidental" criticals
                if (!existing || this.isHigherRisk(riskLevel, existing.risk)) {
                    capabilities.set(cap, {
                        capability: cap,
                        risk: riskLevel,
                        evidence: f.snippet
                    });
                }
            }
        });
        return Array.from(capabilities.values());
    }
    static isHigherRisk(a, b) {
        const levels = { 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4 };
        return levels[a] > levels[b];
    }
}
exports.CapabilityAnalyzer = CapabilityAnalyzer;
