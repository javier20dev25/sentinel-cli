import { RiskSnapshot, RiskTrend } from '../core/risk_history';
export interface TrendDisplayOptions {
    windowDays?: number;
    branch?: string;
    baselineScore?: number;
    baselineCritical?: number;
}
export declare function renderTrend(trend: RiskTrend, opts?: TrendDisplayOptions): string;
export declare function renderSnapshotList(repos: Map<string, RiskSnapshot[]>): string;
