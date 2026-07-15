export interface CapabilitySnapshot {
    packageName: string;
    version: string;
    timestamp: string;
    capabilities: Map<string, number>;
    riskScore: number;
}
export interface DriftEntry {
    capability: string;
    previousCount: number;
    currentCount: number;
    change: number;
    severity: 'NEW' | 'INCREASED' | 'DECREASED' | 'REMOVED';
}
export interface DriftResult {
    packageName: string;
    previousVersion: string;
    currentVersion: string;
    drifts: DriftEntry[];
    riskChange: number;
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    newCapabilities: string[];
    removedCapabilities: string[];
}
export declare function analyzeCapabilities(packageName: string, version: string, packagePath: string): CapabilitySnapshot;
export declare function computeDrift(previous: CapabilitySnapshot, current: CapabilitySnapshot): DriftResult;
export declare function saveSnapshot(snapshot: CapabilitySnapshot): void;
export declare function loadPreviousSnapshot(packageName: string, currentVersion: string): CapabilitySnapshot | null;
