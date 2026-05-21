export interface UserRepo {
    name: string;
    fullName: string;
    description: string;
    visibility: string;
    updatedAt: string;
}
export interface PullRequest {
    number: number;
    title: string;
    author?: {
        login: string;
    };
    updatedAt: string;
    createdAt: string;
    headRefName?: string;
    state?: string;
    url?: string;
    additions?: number;
    deletions?: number;
    changedFiles?: number;
}
export interface DashboardStats {
    totalRepos: number;
    openPRs: number;
    todayPRs: number;
    unanalyzedPRs: number;
    repos: Array<{
        name: string;
        fullName: string;
        openPRs: number;
        todayPRs: number;
        prs: PullRequest[];
    }>;
}
export declare class GitHubBridge {
    isGHInstalled(): {
        installed: boolean;
        version?: string;
    };
    isGitInstalled(): {
        installed: boolean;
        version?: string;
    };
    checkAuth(): {
        authenticated: boolean;
        username?: string;
    };
    login(): Promise<{
        success: boolean;
        username?: string;
        message?: string;
    }>;
    listUserRepos(limit?: number): UserRepo[];
    listPRs(repoFullName: string): PullRequest[];
    getPRDiff(repoFullName: string, prNumber: number): string | null;
    listTodayPRs(repoFullName: string): PullRequest[];
    getDashboardStats(): DashboardStats;
}
export declare const ghBridge: GitHubBridge;
