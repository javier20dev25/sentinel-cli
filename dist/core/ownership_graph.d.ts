import { LiteFinding } from './lite/lite_scanner';
export interface AuthorInfo {
    name: string;
    email: string;
    files: string[];
    findingCount: number;
    riskScore: number;
    topSubcodes: Map<string, number>;
}
export interface OwnershipResult {
    authors: AuthorInfo[];
    totalAuthors: number;
    topAuthor: AuthorInfo | null;
    riskiestAuthor: AuthorInfo | null;
}
export declare function buildOwnershipGraph(findings: LiteFinding[]): Promise<OwnershipResult>;
export interface TeamInfo {
    name: string;
    members: string[];
    files: string[];
    findingCount: number;
    riskScore: number;
}
export declare function parseCodeowners(repoPath: string): Map<string, string[]>;
export declare function groupByTeam(ownership: OwnershipResult, repoPath: string): TeamInfo[];
