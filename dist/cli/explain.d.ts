import { AgencyScoreResult } from '../core/agency_score';
export declare function renderExplain(result: AgencyScoreResult, filePaths: string[]): string;
export declare function explainFiles(targetPaths: string[]): {
    result: AgencyScoreResult;
    files: string[];
};
