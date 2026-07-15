import { LiteFinding } from './lite/lite_scanner';
import { AgencyScoreResult } from './agency_score';
/** @public — frozen contract used by JSON/SARIF/MD exporters */
export interface EvidenceCard {
    subcode: string;
    title: string;
    category: string;
    severity: string;
    riskScore: number;
    confidence: string;
    file: string;
    line: number;
    evidence?: string;
    description: string;
    contribution?: number;
    recommendation?: string;
}
export declare function buildEvidenceCards(findings: LiteFinding[], agencyResult: AgencyScoreResult): EvidenceCard[];
