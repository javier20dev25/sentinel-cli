export interface QuarantineEntry {
    packageName: string;
    version: string;
    originalPath: string;
    quarantinePath: string;
    timestamp: number;
    reason: string;
    severity: string;
}
export interface QuarantineStatus {
    active: boolean;
    entries: QuarantineEntry[];
    quarantineDir: string;
}
export declare class QuarantineManager {
    private sentinelDir;
    private quarantineDir;
    private manifestPath;
    constructor(sentinelDir?: string);
    private ensureDirectories;
    private readManifest;
    private writeManifest;
    getQuarantinePath(packageName: string, version: string): string;
    quarantinePackage(packageName: string, version: string, reason: string, severity: string): QuarantineEntry;
    releasePackage(packageName: string, version: string): boolean;
    status(): QuarantineStatus;
    isQuarantined(packageName: string, version?: string): boolean;
    createPlaceholder(originalPath: string): void;
    removePlaceholder(originalPath: string): void;
    isEnabled(): boolean;
}
