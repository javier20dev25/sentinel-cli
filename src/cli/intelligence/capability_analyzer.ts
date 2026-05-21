/**
 * Sentinel Capability Analyzer (v1.0)
 * 
 * Maps low-level findings to high-level 'Capabilities' for Governance.
 */

import { LiteFinding } from '../../core/lite/lite_scanner';

export type CapabilityType = 'NETWORK' | 'FILESYSTEM' | 'PROCESS_EXEC' | 'ENV_ACCESS' | 'DYNAMIC_EXEC' | 'DOM_MANIPULATION' | 'CREDENTIAL_LEAK';

export interface PackageCapability {
    capability: CapabilityType;
    risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    evidence: string;
}

export class CapabilityAnalyzer {
    /**
     * Maps findings from a scan to high-level capabilities.
     */
    public static analyze(findings: LiteFinding[]): PackageCapability[] {
        const capabilities: Map<CapabilityType, PackageCapability> = new Map();

        findings.forEach(f => {
            let cap: CapabilityType | null = null;
            
            switch (f.type) {
                case 'NETWORK_ACTIVITY': cap = 'NETWORK'; break;
                case 'OS_CAPABILITY': cap = 'PROCESS_EXEC'; break;
                case 'ENV_ACCESS': cap = 'ENV_ACCESS'; break;
                case 'UNSAFE_EVAL': cap = 'DYNAMIC_EXEC'; break;
                case 'DOM_INJECTION': cap = 'DOM_MANIPULATION'; break;
                case 'SANDBOX_ESCAPE': cap = 'PROCESS_EXEC'; break;
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
                case 'SECRET_HARDCODED_TOKEN': cap = 'CREDENTIAL_LEAK'; break;
            }

            if (cap) {
                const existing = capabilities.get(cap);
                // Escalate risk if intent is MALICIOUS
                let riskLevel = f.severity;
                if (f.intent === 'MALICIOUS') riskLevel = 'CRITICAL';
                if (f.intent === 'VULNERABILITY' && riskLevel === 'CRITICAL') riskLevel = 'HIGH'; // Downgrade "accidental" criticals

                if (!existing || this.isHigherRisk(riskLevel, existing.risk)) {
                    capabilities.set(cap, {
                        capability: cap,
                        risk: riskLevel as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
                        evidence: f.snippet
                    });
                }
            }
        });

        return Array.from(capabilities.values());
    }

    private static isHigherRisk(a: string, b: string): boolean {
        const levels: Record<string, number> = { 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4 };
        return levels[a] > levels[b];
    }
}
