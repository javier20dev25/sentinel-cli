import { LiteFinding } from './lite/lite_scanner';
import { RiskSnapshot } from './risk_history';
import { AgencyScoreResult } from './agency_score';
export interface FindingDelta {
    newFindings: LiteFinding[];
    fixedFindings: {
        subcode: string;
        file: string;
        line: number;
        title: string;
    }[];
    scoreDelta: number;
    criticalDelta: number;
    highDelta: number;
    totalBefore: number;
    totalAfter: number;
}
export declare function computeDelta(currentFindings: LiteFinding[], snapshot: RiskSnapshot, previousFindings?: LiteFinding[]): FindingDelta;
export declare function computeDeltaVsLatest(currentFindings: LiteFinding[], repoPath: string): {
    delta: FindingDelta | null;
    baseline: RiskSnapshot | null;
};
export declare function computeDeltaVsBaseline(currentFindings: LiteFinding[], currentAgency: AgencyScoreResult, repoPath: string, baselineBranch?: string): {
    delta: FindingDelta | null;
    baseline: RiskSnapshot | null;
};
