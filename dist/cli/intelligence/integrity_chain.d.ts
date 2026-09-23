export interface ChainLink {
    id: number;
    session_id: string;
    link_number: number;
    code_hash: string;
    previous_link_hash: string | null;
    link_hash: string;
    started_at: string;
    accumulated_seconds: number;
    created_at: string;
    [key: string]: unknown;
}
export interface ChainStatus {
    status: 'INTACT' | 'BROKEN' | 'EMPTY';
    totalLinks: number;
    currentCodeHash: string;
    lastLink: ChainLink | null;
    accumulatedSeconds: number;
    sessionSeconds: number;
    chainStart: string;
    lastVerified: string;
}
export declare class IntegrityChain {
    private db;
    private cliRoot;
    private sessionId;
    private sessionStart;
    constructor(dbPath?: string);
    private initSchema;
    recordBoot(codeHash: string): {
        chainStatus: ChainStatus;
    };
    getStatus(): ChainStatus;
    private getLastLink;
    private getAllLinks;
    private getTotalLinks;
    private schemaVersion;
    private pickFields;
    private hashForSchema;
    /**
     * Verifies a single link's own link_hash using the schema that created it.
     * The link_hash covers exactly the 6 canonical fields; id and created_at
     * are not part of a link's own signed material.
     */
    verifyLink(link: ChainLink): boolean;
    formatDuration(totalSeconds: number): string;
}
