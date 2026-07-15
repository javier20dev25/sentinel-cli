export interface TokenInspectResult {
    tokenType: string;
    provider: string;
    riskScore: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    confidence: 'high' | 'medium' | 'low';
    summary: string;
    details?: {
        scopes?: string[];
        expiration?: string;
        lastUsed?: string;
    };
    recommendations: string[];
}
export declare function inspectToken(token: string, options?: {
    check?: boolean;
}): Promise<TokenInspectResult>;
export declare function formatInspectResult(result: TokenInspectResult): string;
