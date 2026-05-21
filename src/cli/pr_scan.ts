import { LiteScanner } from '../core/lite/lite_scanner';
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

    const scanner = new LiteScanner();
    const result = await scanner.auditPR(repo, prNumber, author, files);

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
        contentHash
    };

    console.log(JSON.stringify(output));
}

main().catch(err => {
    process.stderr.write(`[pr_scan] ERROR: ${err.stack || err.message}\n`);
    console.log(JSON.stringify({ error: err.message }));
    process.exit(1);
});
