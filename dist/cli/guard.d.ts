/**
 * Sentinel Guard (v1.1)
 *
 * Provisions OS-level package manager interception via shell profile aliases.
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
