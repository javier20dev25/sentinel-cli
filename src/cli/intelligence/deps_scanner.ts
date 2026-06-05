/**
 * Sentinel Dependency Tree Scanner (v5.0)
 *
 * Walks the dependency tree from package.json up to depth 3,
 * scans each package with LiteScanner, and reports threats.
 */

import * as fs from 'fs';
import * as path from 'path';
import { LiteScanner, LiteFinding } from '../../core/lite/lite_scanner';

export interface DepNode {
    name: string;
    version: string;
    depth: number;
    path: string;
}

export interface DepScanResult {
    nodes: DepNode[];
    findings: { node: DepNode; findings: LiteFinding[] }[];
    totalFindings: number;
    criticalCount: number;
}

export class DepsScanner {
    private scanner: LiteScanner;
    private scanned: Set<string>;

    constructor() {
        this.scanner = new LiteScanner();
        this.scanned = new Set();
    }

    /**
     * Resolve the real installed version of a package from node_modules.
     */
    private resolveVersion(pkgDir: string): string {
        try {
            const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
            return pkgJson.version || 'unknown';
        } catch {
            return 'unknown';
        }
    }

    /**
     * Walk the dependency tree starting from a node_modules directory.
     */
    public walkTree(nodeModulesPath: string, maxDepth: number = 3): DepNode[] {
        const nodes: DepNode[] = [];
        this.walkDir(nodeModulesPath, nodes, 0, maxDepth);
        return nodes;
    }

    private walkDir(dir: string, nodes: DepNode[], depth: number, maxDepth: number): void {
        if (depth > maxDepth) return;
        if (!fs.existsSync(dir)) return;

        let entries: string[];
        try {
            entries = fs.readdirSync(dir);
        } catch {
            return;
        }

        for (const entry of entries) {
            if (entry.startsWith('.')) continue;
            const fullPath = path.join(dir, entry);

            let stat: fs.Stats;
            try { stat = fs.statSync(fullPath); } catch { continue; }
            if (!stat.isDirectory()) continue;

            if (entry.startsWith('@')) {
                // Scoped package
                const scopedEntries = fs.readdirSync(fullPath);
                for (const sub of scopedEntries) {
                    const subPath = path.join(fullPath, sub);
                    if (fs.statSync(subPath).isDirectory()) {
                        const name = `${entry}/${sub}`;
                        if (this.scanned.has(name)) continue;
                        this.scanned.add(name);
                        nodes.push({
                            name,
                            version: this.resolveVersion(subPath),
                            depth,
                            path: subPath
                        });
                        // Walk its node_modules for transitive deps
                        const nmPath = path.join(subPath, 'node_modules');
                        if (fs.existsSync(nmPath)) {
                            this.walkDir(nmPath, nodes, depth + 1, maxDepth);
                        }
                    }
                }
            } else {
                if (entry === 'node_modules' || entry === '.bin' || entry === '.cache') continue;
                const name = entry;
                if (this.scanned.has(name)) continue;
                this.scanned.add(name);
                nodes.push({
                    name,
                    version: this.resolveVersion(fullPath),
                    depth,
                    path: fullPath
                });
                // Walk its node_modules for transitive deps
                const nmPath = path.join(fullPath, 'node_modules');
                if (fs.existsSync(nmPath)) {
                    this.walkDir(nmPath, nodes, depth + 1, maxDepth);
                }
            }
        }
    }

    /**
     * Scan all nodes in the dependency tree with LiteScanner.
     */
    public scanTree(nodes: DepNode[]): DepScanResult {
        const result: DepScanResult = {
            nodes,
            findings: [],
            totalFindings: 0,
            criticalCount: 0
        };

        for (const node of nodes) {
            try {
                const files = this.walkPkgFiles(node.path);
                const nodeFindings: LiteFinding[] = [];

                for (const file of files) {
                    try {
                        const content = fs.readFileSync(file, 'utf8');
                        const relPath = path.relative(node.path, file);
                        const scanResult = this.scanner.scanFileContent(relPath, content);
                        nodeFindings.push(...scanResult.findings);
                    } catch {}
                }

                if (nodeFindings.length > 0) {
                    result.findings.push({ node, findings: nodeFindings });
                    result.totalFindings += nodeFindings.length;
                    result.criticalCount += nodeFindings.filter(f => f.severity === 'CRITICAL').length;
                }
            } catch {}
        }

        return result;
    }

    private walkPkgFiles(dir: string): string[] {
        const files: string[] = [];
        const walk = (d: string, depth: number) => {
            if (depth > 3) return;
            try {
                const entries = fs.readdirSync(d);
                for (const e of entries) {
                    if (e.startsWith('.') || e === 'node_modules' || e === '.bin') continue;
                    const full = path.join(d, e);
                    const stat = fs.statSync(full);
                    if (stat.isDirectory()) {
                        walk(full, depth + 1);
                    } else if (e.endsWith('.js') || e.endsWith('.ts') || e.endsWith('.mjs') || e.endsWith('.cjs') || e.endsWith('.gyp') || e.endsWith('.sh') || e === 'package.json') {
                        files.push(full);
                    }
                }
            } catch {}
        };
        walk(dir, 0);
        return files;
    }
}
