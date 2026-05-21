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
export declare class CapabilityAnalyzer {
    /**
     * Maps findings from a scan to high-level capabilities.
     */
    static analyze(findings: LiteFinding[]): PackageCapability[];
    private static isHigherRisk;
}
