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
    /**
     * Detects lockfiles that are recognized by filename but NOT parseable by this
     * parser (pnpm, Yarn Berry). Returns a human-readable reason, or null when the
     * file is either supported or unrecognized. This lets callers report an
     * explicit INCOMPLETE status instead of a misleading "no dependencies".
     */
    detectUnsupported(filename: string, content: string): string | null;
    detectFormat(content: string): string;
    parsePackageLock(content: string): LockfileResult;
    private parseNpmV7;
    private parseNpmV6;
    parseYarnLock(content: string): LockfileResult;
    parse(path: string): LockfileResult;
}
