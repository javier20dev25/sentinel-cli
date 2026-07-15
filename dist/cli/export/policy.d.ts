import { AgencyScoreResult } from '../../core/agency_score';
import { LiteFinding } from '../../core/lite/lite_scanner';
export interface PolicyResult {
    shouldFail: boolean;
    reason: string;
}
export interface PolicyOptions {
    failOnScore?: number;
    failOnCritical?: boolean;
    failOnHigh?: boolean;
    failOnVerdict?: 'BLOCK' | 'REVIEW';
}
export declare function evaluatePolicy(findings: LiteFinding[], agency: AgencyScoreResult, options: PolicyOptions): PolicyResult;
