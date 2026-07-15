export interface ReputationFactor {
    name: string;
    impact: number;
    detail: string;
}
export interface ReputationScore {
    packageName: string;
    version: string;
    score: number;
    label: 'TRUSTED' | 'NEUTRAL' | 'SUSPICIOUS' | 'MALICIOUS';
    factors: ReputationFactor[];
}
export declare class RegistryReputation {
    score(packageName: string): Promise<ReputationScore>;
    npmView(packageName: string): Promise<any>;
    private calculateScore;
    getLabel(score: number): 'TRUSTED' | 'NEUTRAL' | 'SUSPICIOUS' | 'MALICIOUS';
}
