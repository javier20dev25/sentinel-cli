import { GraphSnapshot } from '../core/graph_persistence';
export declare function renderGraphHistory(snapshots: GraphSnapshot[]): string;
export declare function renderGraphDiff(before: GraphSnapshot | null, after: GraphSnapshot): string;
