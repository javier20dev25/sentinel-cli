import { LiteFinding } from './lite/lite_scanner';
import { AgencyScoreResult } from './agency_score';
import { EvidenceCard } from './evidence_card';
import { AttackScenario } from './attack_scenario';
import { AgencyGraph } from './agency_graph';
export interface EvidenceItem {
    subcode: string;
    title: string;
    file: string;
    line: number;
    severity: string;
    riskScore: number;
    detail: string;
}
export interface EvidencePack {
    id: string;
    title: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    score: number;
    confidence: number;
    narrative: string;
    impact: string;
    evidenceItems: EvidenceItem[];
    remediationSteps: string[];
    affectedAssets: string[];
    chainLength: number;
}
export declare function buildEvidencePacks(scenarios: AttackScenario[], graph: AgencyGraph, findings: LiteFinding[], cards: EvidenceCard[], agency: AgencyScoreResult): EvidencePack[];
