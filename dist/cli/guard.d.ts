/**
 * Sentinel Guard (v2.0)
 *
 * Multi-layer OS-level package manager interception:
 * 1. PATH-based wrappers (~/.sentinel/bin/*) — harder to bypass
 * 2. Shell profile PATH prepend to ensure wrappers are found first
 * 3. Legacy shell aliases (fallback)
 *
 * Makes Sentinel ineludible — even when the user types 'npm install' directly.
 */
export declare const SUPPORTED_MANAGERS: string[];
export declare function getShellProfilePath(): string;
export interface GuardResult {
    success: boolean;
    reason?: string;
    profilePath?: string;
    managers?: string[];
}
export declare function enableGuard(): GuardResult;
export declare function disableGuard(): GuardResult;
export declare function isGuardEnabled(): boolean;
