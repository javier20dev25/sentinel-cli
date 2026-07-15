import { LiteFinding } from './lite/lite_scanner';
import { AgencyScoreResult } from './agency_score';
export declare enum EdgeType {
    CAUSAL = "causal",
    CORRELATED = "correlated",
    SAME_FILE = "same_file"
}
export interface GraphNode {
    id: string;
    subcode: string;
    title: string;
    severity: string;
    riskScore: number;
    contribution: number;
    file: string;
    line: number;
    category: string;
    evidence?: string;
}
export interface GraphEdge {
    sourceId: string;
    targetId: string;
    type: EdgeType;
    confidence: number;
    label: string;
}
export interface GraphChain {
    nodes: GraphNode[];
    score: number;
    confidence: number;
}
export interface AgencyGraph {
    nodes: GraphNode[];
    edges: GraphEdge[];
    chains: GraphChain[];
}
export declare function buildAgencyGraph(findings: LiteFinding[], agency: AgencyScoreResult): AgencyGraph;
