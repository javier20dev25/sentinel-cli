import { LiteFinding } from '../../core/lite/lite_scanner';
import { AgencyScoreResult } from '../../core/agency_score';
import { EvidenceCard } from '../../core/evidence_card';
export interface EnrichedJsonOutput {
    host: string;
    scanTimeMs: number;
    memoryMB: number;
    totalFindings: number;
    agencyScore: number;
    verdict: string;
    blastRadius: string;
    drivers: {
        subcode: string;
        title: string;
        category: string;
        riskScore: number;
        contribution: number;
        confidence: string;
    }[];
    cards: {
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
    }[];
    findings: LiteFinding[];
}
export declare function renderEnrichedJson(findings: LiteFinding[], agency: AgencyScoreResult, cards: EvidenceCard[], meta: {
    host: string;
    scanTimeMs: number;
    memoryMB: number;
}): string;
