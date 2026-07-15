export interface ClassifiedToken {
    tokenType: string;
    provider: string;
    riskScore: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    confidence: 'high' | 'medium' | 'low';
}
export declare const PERMISSION_SCORES: Record<string, number>;
export declare function calculateRiskScore(baseScore: number, permissions?: string[]): number;
export declare function classifyToken(token: string): ClassifiedToken;
export declare function extractTokenValue(snippet: string, secretType: string): string | null;
