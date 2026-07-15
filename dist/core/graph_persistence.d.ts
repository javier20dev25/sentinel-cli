import { AgencyGraph } from './agency_graph';
export interface GraphSnapshot {
    id: string;
    timestamp: string;
    repoHash: string;
    nodes: number;
    edges: number;
    chains: number;
    topChains: Array<{
        score: number;
        confidence: number;
        nodeCount: number;
    }>;
    fullGraph: AgencyGraph;
}
export declare function saveGraphSnapshot(repoPath: string, graph: AgencyGraph): string;
export declare function loadGraphHistory(repoPath: string): GraphSnapshot[];
export declare function computeGraphTrend(repoPath: string): {
    chainCountDelta: number;
    scoreDelta: number;
};
