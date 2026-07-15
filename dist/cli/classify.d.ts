/**
 * Sentinel Classified (v1.1)
 *
 * Protects sensitive files by marking them as "Classified" and enforcing
 * local pre-commit hooks to prevent exfiltration.
 */
interface ClassifiedDb {
    [repoPath: string]: string[];
}
export declare function readClassifiedDb(): ClassifiedDb;
export declare function saveClassifiedDb(db: ClassifiedDb): void;
/**
 * Finds local git repos up to depth 2 in common directories.
 */
export declare function findLocalProjects(): string[];
export declare function getProjectFiles(dir: string): string[];
export declare function installPreCommitHook(repoPath: string, lang?: string): boolean;
export declare function checkClassifiedHook(repoPath: string): number;
/**
 * Get list of files staged in git (git diff --cached --name-only).
 */
export declare function getStagedFiles(repoPath?: string): string[];
/**
 * Install a pre-commit hook that runs SAST scan on staged files,
 * then checks classified files. Preserves existing hooks.
 */
export declare function installSastPreCommitHook(repoPath: string): boolean;
/**
 * Remove the Sentinel SAST pre-commit hook. Preserves any non-Sentinel hooks.
 */
export declare function uninstallPreCommitHook(repoPath: string): boolean;
/**
 * Check if the Sentinel SAST pre-commit hook is installed.
 */
export declare function isPreCommitHookInstalled(repoPath: string): boolean;
export declare function handleClassifiedMenu(lang: string, askQuestion: (query: string) => Promise<string>): Promise<void>;
export {};
