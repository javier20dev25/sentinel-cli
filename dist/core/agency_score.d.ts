import { LiteFinding } from './lite/lite_scanner';
export interface AgencyDriver {
    subcode: string;
    title: string;
    category: string;
    riskScore: number;
    contribution: number;
    confidence: string;
    file: string;
    line: number;
}
export interface AgencyCorrelation {
    description: string;
    bonus: number;
    involved: string[];
}
export interface AgencyScoreResult {
    agencyScore: number;
    blastRadius: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    verdict: 'PASS' | 'REVIEW' | 'BLOCK';
    drivers: AgencyDriver[];
    correlations: AgencyCorrelation[];
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    recommendation: string;
}
export declare function detectCorrelations(findings: LiteFinding[]): AgencyCorrelation[];
export declare function generateRecommendation(findings: LiteFinding[], drivers: AgencyDriver[]): string;
export declare function calculateAgencyScore(findings: LiteFinding[]): AgencyScoreResult;
