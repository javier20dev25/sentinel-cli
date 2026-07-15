/**
 * Sentinel Dependency Tree Scanner (v5.0)
 *
 * Walks the dependency tree from package.json up to depth 3,
 * scans each package with LiteScanner, and reports threats.
 */
import { LiteFinding } from '../../core/lite/lite_scanner';
export interface DepNode {
    name: string;
    version: string;
    depth: number;
    path: string;
}
export interface DepScanResult {
    nodes: DepNode[];
    findings: {
        node: DepNode;
        findings: LiteFinding[];
    }[];
    totalFindings: number;
    criticalCount: number;
}
export declare class DepsScanner {
    private scanner;
    private scanned;
    constructor();
    /**
     * Resolve the real installed version of a package from node_modules.
     */
    private resolveVersion;
    /**
     * Walk the dependency tree starting from a node_modules directory.
     */
    walkTree(nodeModulesPath: string, maxDepth?: number): DepNode[];
    private walkDir;
    /**
     * Scan all nodes in the dependency tree with LiteScanner.
     */
    scanTree(nodes: DepNode[]): DepScanResult;
    private walkPkgFiles;
}
