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
 * A staged change with its git status. For renames, `oldFile` carries the
 * original path so the caller can diff against it and keep real hunks instead
 * of degrading to a full-file "new" patch (which would re-introduce false
 * attribution on pre-existing lines).
 */
export interface StagedChange {
    file: string;
    oldFile?: string;
    status: string;
}
/**
 * Get staged changes with git status (git diff --cached --name-status -z).
 *
 * Includes A/C/M/R/T so a rename-with-modification is NOT skipped: a file that
 * is renamed and modified in the same commit would otherwise fall through
 * --diff-filter=ACM and its new lines would never be scanned.
 */
export declare function getStagedChanges(repoPath?: string): StagedChange[];
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
