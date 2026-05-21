import { LiteScanner } from '../core/lite/lite_scanner';
import { SupplyChainShield } from './intelligence/supply_chain_shield';
import { createHash } from 'crypto';
import { readFileSync } from 'fs';

function parseUnifiedDiff(raw: string): { filename: string; patch: string }[] {
    const clean = raw.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
    const parts = clean.split(/(?=^diff --git )/m);
    const files: { filename: string; patch: string }[] = [];

    for (const part of parts) {
        const trimmed = part.trim();
        if (!trimmed) continue;
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

function parsePackageChanges(files: { filename: string; patch: string }[]): string[] {
    const pkgs = new Set<string>();

    for (const file of files) {
        if (!file.filename.endsWith('package.json')) continue;

        const lines = file.patch.split('\n');
        let inDeps = false;

        for (const line of lines) {
            if (line.startsWith('---') || line.startsWith('@@') || line.startsWith('diff')) continue;
            const content = line.substring(1);

            if (content.includes('"dependencies"') || content.includes('"devDependencies"') || content.includes('"peerDependencies"')) {
                if (!line.startsWith('-')) inDeps = true;
                continue;
            }

            if (inDeps && (content.trim() === '}' || content.trim() === '},')) {
                inDeps = false;
                continue;
            }

            if (line.startsWith('+') && inDeps) {
                const match = content.match(/"(@[^"@\s]+\/[^"@\s]+|[a-z0-9_-][^"@\s]*)"\s*:/);
                if (match) {
                    let pkg = match[1].trim();
                    if (pkg.endsWith(',')) pkg = pkg.slice(0, -1).trim();
                    if (pkg) pkgs.add(pkg);
                }
            }
        }
    }

    return [...pkgs];
}

async function main() {
    const diffFile = process.argv[2];
    if (!diffFile) {
        process.stderr.write('Usage: node pr_scan.js <diff_file>\n');
        process.exit(1);
    }

    const diff = readFileSync(diffFile, 'utf8');
    const repo = process.env.SENTINEL_REPO || 'unknown';
    const prNumber = parseInt(process.env.SENTINEL_PR || '0', 10);
    const author = process.env.SENTINEL_AUTHOR || 'unknown';

    const files = parseUnifiedDiff(diff);
    process.stderr.write(`[pr_scan] files=${files.length} diffBytes=${diff.length}\n`);

    // SAST scan
    const scanner = new LiteScanner();
    const result = await scanner.auditPR(repo, prNumber, author, files);

    // Supply chain scan
    const changedPkgs = parsePackageChanges(files);
    let supplyChain: any[] = [];

    if (changedPkgs.length > 0) {
        process.stderr.write(`[pr_scan] supplyChain: ${changedPkgs.join(', ')}\n`);
        const shield = new SupplyChainShield();
        const batchSize = Math.min(changedPkgs.length, 5);
        const results = await shield.analyzeBatch(changedPkgs.slice(0, batchSize));
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

    const contentHash = createHash('sha256').update(diff, 'utf8').digest('hex');

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
}

main().catch(err => {
    process.stderr.write(`[pr_scan] ERROR: ${err.stack || err.message}\n`);
    console.log(JSON.stringify({ error: err.message }));
    process.exit(1);
});
