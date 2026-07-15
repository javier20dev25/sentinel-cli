interface WorkflowOptions {
    repo?: string;
    prNumber?: number;
    owner?: string;
    comment?: boolean;
    checkRun?: boolean;
}
export declare function prReview(opts: WorkflowOptions): Promise<void>;
export declare function fullAudit(opts: WorkflowOptions): Promise<void>;
export {};
