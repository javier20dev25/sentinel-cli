import { AgencyScoreResult } from './agency_score';
import { AttackScenario } from './attack_scenario';
export interface RiskSnapshot {
    id: string;
    timestamp: string;
    agencyScore: number;
    verdict: string;
    blastRadius: string;
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    scenarioCount: number;
    topScenarios: {
        id: string;
        name: string;
        score: number;
        severity: string;
    }[];
    repoPath: string;
    repoHash: string;
    branch?: string;
}
export interface RiskTrend {
    snapshots: RiskSnapshot[];
    direction: 'improving' | 'declining' | 'stable';
    scoreDelta: number;
    findingDelta: number;
    criticalDelta: number;
}
export declare function repoHash(repoPath: string): string;
export declare function saveSnapshot(repoPath: string, agency: AgencyScoreResult, scenarios: AttackScenario[], branch?: string): RiskSnapshot;
export declare function loadHistory(repoPath: string): RiskSnapshot[];
export declare function loadBaseline(repoPath: string): RiskSnapshot | null;
export declare function loadHistoryInWindow(repoPath: string, days: number): RiskSnapshot[];
export declare function computeTrendInWindow(repoPath: string, days: number): RiskTrend;
export declare function loadAllHistory(): Map<string, RiskSnapshot[]>;
export declare function computeTrend(snapshots: RiskSnapshot[]): RiskTrend;
