import { AgencyScoreResult } from './agency_score';
import { GraphChain } from './agency_graph';
export interface AttackScenario {
    id: string;
    name: string;
    description: string;
    impact: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    score: number;
    confidence: number;
    evidence: string[];
    chain: GraphChain;
}
export declare function buildScenarios(chains: GraphChain[], agency: AgencyScoreResult): AttackScenario[];
