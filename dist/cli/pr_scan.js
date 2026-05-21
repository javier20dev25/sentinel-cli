"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const lite_scanner_1 = require("../core/lite/lite_scanner");
const supply_chain_shield_1 = require("./intelligence/supply_chain_shield");
const crypto_1 = require("crypto");
const fs_1 = require("fs");
function parseUnifiedDiff(raw) {
    const clean = raw.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
    const parts = clean.split(/(?=^diff --git )/m);
    const files = [];
    for (const part of parts) {
        const trimmed = part.trim();
        if (!trimmed)
            continue;
        const m = trimmed.match(/^diff --git a\/\S+ b\/(.+)$/m);
        if (m) {
            files.push({ filename: m[1].trim(), patch: trimmed });
        }
    }
    if (files.length === 0 && clean.trim()) {
        const m = clean.match(/^\+\+\+ b\/(.+)$/m);
        const filename = m ? m[1].trim() : 'PR.diff';
        files.push({ filename, patch: clean });
    }
    return files;
}
function parsePackageChanges(files) {
    const pkgs = new Set();
    for (const file of files) {
        if (!file.filename.endsWith('package.json'))
            continue;
        const lines = file.patch.split('\n');
        let inDeps = false;
        for (const line of lines) {
            if (line.startsWith('+') && !line.startsWith('+++')) {
                const content = line.substring(1);
                if (content.includes('"dependencies"') || content.includes('"devDependencies"') || content.includes('"peerDependencies"')) {
                    inDeps = true;
                    continue;
                }
                if (inDeps && content.trim() === '}') {
                    inDeps = false;
                    continue;
                }
                if (inDeps && content.trim() === '},') {
                    inDeps = false;
                    continue;
                }
                if (inDeps) {
                    const match = content.match(/"(@[^"@\s]+\/[^"@\s]+|[a-z0-9][^"@\s]*)"\s*:/);
                    if (match) {
                        let pkg = match[1].trim();
                        if (pkg.endsWith(','))
                            pkg = pkg.slice(0, -1).trim();
                        if (pkg)
                            pkgs.add(pkg);
                    }
                }
            }
            if (line.startsWith('-') && !line.startsWith('---')) {
                const content = line.substring(1);
                if (content.includes('"dependencies"') || content.includes('"devDependencies"') || content.includes('"peerDependencies"')) {
                    inDeps = false;
                }
            }
        }
    }
    return [...pkgs];
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        const diffFile = process.argv[2];
        if (!diffFile) {
            process.stderr.write('Usage: node pr_scan.js <diff_file>\n');
            process.exit(1);
        }
        const diff = (0, fs_1.readFileSync)(diffFile, 'utf8');
        const repo = process.env.SENTINEL_REPO || 'unknown';
        const prNumber = parseInt(process.env.SENTINEL_PR || '0', 10);
        const author = process.env.SENTINEL_AUTHOR || 'unknown';
        const files = parseUnifiedDiff(diff);
        process.stderr.write(`[pr_scan] files=${files.length} diffBytes=${diff.length}\n`);
        // SAST scan
        const scanner = new lite_scanner_1.LiteScanner();
        const result = yield scanner.auditPR(repo, prNumber, author, files);
        // Supply chain scan
        const changedPkgs = parsePackageChanges(files);
        let supplyChain = [];
        if (changedPkgs.length > 0) {
            process.stderr.write(`[pr_scan] supplyChain: ${changedPkgs.join(', ')}\n`);
            const shield = new supply_chain_shield_1.SupplyChainShield();
            const batchSize = Math.min(changedPkgs.length, 5);
            const results = yield shield.analyzeBatch(changedPkgs.slice(0, batchSize));
            supplyChain = results.map(r => ({
                package: r.pkg,
                verdict: r.verdict,
                fileCount: r.fileCount,
                scanTimeMs: r.scanTimeMs,
                sizeBytes: r.sizeBytes,
                findings: r.findings.map(f => ({
                    type: f.type,
                    intent: f.intent,
                    file: f.file,
                    line: f.line,
                    severity: f.severity,
                    description: f.description,
                    snippet: f.snippet.substring(0, 200)
                }))
            }));
            if (changedPkgs.length > batchSize) {
                supplyChain.push({
                    package: `... and ${changedPkgs.length - batchSize} more`,
                    verdict: 'SKIPPED',
                    fileCount: 0,
                    scanTimeMs: 0,
                    sizeBytes: 0,
                    findings: []
                });
            }
        }
        const contentHash = (0, crypto_1.createHash)('sha256').update(diff, 'utf8').digest('hex');
        const output = {
            scanId: result.scanId,
            findings: result.findings.map(f => ({
                type: f.type,
                intent: f.intent,
                file: f.file,
                line: f.line,
                severity: f.severity,
                description: f.description,
                snippet: f.snippet.substring(0, 200)
            })),
            filesAnalyzed: files.length,
            correlations: result.correlations.length,
            verdict: result.verdict,
            supplyChain,
            contentHash
        };
        console.log(JSON.stringify(output));
    });
}
main().catch(err => {
    process.stderr.write(`[pr_scan] ERROR: ${err.stack || err.message}\n`);
    console.log(JSON.stringify({ error: err.message }));
    process.exit(1);
});
