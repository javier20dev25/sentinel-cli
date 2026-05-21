/**
 * Sentinel Integrity Manager (v1.0)
 *
 * Ensures the CLI and its environment are not tampered with.
 * Levels: TRUSTED | SUSPECT | COMPROMISED
 */
export type IntegrityLevel = 'TRUSTED' | 'SUSPECT' | 'COMPROMISED';
export declare class IntegrityManager {
    private cliRoot;
    private vaultPath;
    constructor();
    /**
     * Performs a full system integrity audit.
     */
    checkIntegrity(): Promise<{
        level: IntegrityLevel;
        reasons: string[];
    }>;
    private calculateRulesHash;
    private verifySignedManifest;
    report(level: IntegrityLevel, reasons: string[]): void;
}
