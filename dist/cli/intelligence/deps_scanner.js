"use strict";
/**
 * Sentinel Dependency Tree Scanner (v5.0)
 *
 * Walks the dependency tree from package.json up to depth 3,
 * scans each package with LiteScanner, and reports threats.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.DepsScanner = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const lite_scanner_1 = require("../../core/lite/lite_scanner");
class DepsScanner {
    constructor() {
        this.scanner = new lite_scanner_1.LiteScanner();
        this.scanned = new Set();
    }
    /**
     * Resolve the real installed version of a package from node_modules.
     */
    resolveVersion(pkgDir) {
        try {
            const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
            return pkgJson.version || 'unknown';
        }
        catch (_a) {
            return 'unknown';
        }
    }
    /**
     * Walk the dependency tree starting from a node_modules directory.
     */
    walkTree(nodeModulesPath, maxDepth = 3) {
        const nodes = [];
        this.walkDir(nodeModulesPath, nodes, 0, maxDepth);
        return nodes;
    }
    walkDir(dir, nodes, depth, maxDepth) {
        if (depth > maxDepth)
            return;
        if (!fs.existsSync(dir))
            return;
        let entries;
        try {
            entries = fs.readdirSync(dir);
        }
        catch (_a) {
            return;
        }
        for (const entry of entries) {
            if (entry.startsWith('.'))
                continue;
            const fullPath = path.join(dir, entry);
            let stat;
            try {
                stat = fs.statSync(fullPath);
            }
            catch (_b) {
                continue;
            }
            if (!stat.isDirectory())
                continue;
            if (entry.startsWith('@')) {
                // Scoped package
                const scopedEntries = fs.readdirSync(fullPath);
                for (const sub of scopedEntries) {
                    const subPath = path.join(fullPath, sub);
                    if (fs.statSync(subPath).isDirectory()) {
                        const name = `${entry}/${sub}`;
                        if (this.scanned.has(name))
                            continue;
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
            }
            else {
                if (entry === 'node_modules' || entry === '.bin' || entry === '.cache')
                    continue;
                const name = entry;
                if (this.scanned.has(name))
                    continue;
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
    scanTree(nodes) {
        const result = {
            nodes,
            findings: [],
            totalFindings: 0,
            criticalCount: 0
        };
        for (const node of nodes) {
            try {
                const files = this.walkPkgFiles(node.path);
                const nodeFindings = [];
                for (const file of files) {
                    try {
                        const content = fs.readFileSync(file, 'utf8');
                        const relPath = path.relative(node.path, file);
                        const scanResult = this.scanner.scanFileContent(relPath, content);
                        nodeFindings.push(...scanResult.findings);
                    }
                    catch (_a) { }
                }
                if (nodeFindings.length > 0) {
                    result.findings.push({ node, findings: nodeFindings });
                    result.totalFindings += nodeFindings.length;
                    result.criticalCount += nodeFindings.filter(f => f.severity === 'CRITICAL').length;
                }
            }
            catch (_b) { }
        }
        return result;
    }
    walkPkgFiles(dir) {
        const files = [];
        const walk = (d, depth) => {
            if (depth > 3)
                return;
            try {
                const entries = fs.readdirSync(d);
                for (const e of entries) {
                    if (e.startsWith('.') || e === 'node_modules' || e === '.bin')
                        continue;
                    const full = path.join(d, e);
                    const stat = fs.statSync(full);
                    if (stat.isDirectory()) {
                        walk(full, depth + 1);
                    }
                    else if (e.endsWith('.js') || e.endsWith('.ts') || e.endsWith('.mjs') || e.endsWith('.cjs') || e.endsWith('.gyp') || e.endsWith('.sh') || e === 'package.json') {
                        files.push(full);
                    }
                }
            }
            catch (_a) { }
        };
        walk(dir, 0);
        return files;
    }
}
exports.DepsScanner = DepsScanner;
