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
export declare function handleClassifiedMenu(lang: string, askQuestion: (query: string) => Promise<string>): Promise<void>;
export {};
