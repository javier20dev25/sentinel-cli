export interface CiConfig {
    repo: string;
    prNumber: number;
    token: string;
    findingsCount: number;
    agencyScore: number;
    verdict: string;
    markdownReport: string;
}
export interface CiResult {
    posted: boolean;
    url?: string;
    error?: string;
}
export declare function detectCiEnv(): {
    isCi: boolean;
    repo?: string;
    prNumber?: number;
    token?: string;
};
export declare function postPrComment(config: CiConfig): Promise<CiResult>;
