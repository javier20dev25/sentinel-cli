export interface LockfileEntry {
    name: string;
    version: string;
    resolved: string;
    integrity: string;
    dependencies: string[];
}
export interface LockfileResult {
    entries: LockfileEntry[];
    format: 'npm-v6' | 'npm-v7' | 'yarn' | 'unknown';
}
export declare class LockfileParser {
    detectFormat(content: string): string;
    parsePackageLock(content: string): LockfileResult;
    private parseNpmV7;
    private parseNpmV6;
    parseYarnLock(content: string): LockfileResult;
    parse(path: string): LockfileResult;
}
