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
const signal_vault_1 = require("./intelligence/signal_vault");
const crypto_1 = require("crypto");
const fs_1 = require("fs");
function parseUnifiedDiff(raw) {
    const parts = raw.split(/(?=^diff --git )/m);
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
    if (files.length === 0 && raw.trim()) {
        const m = raw.match(/^\+\+\+ b\/(.+)$/m);
        const filename = m ? m[1].trim() : 'PR.diff';
        files.push({ filename, patch: raw });
    }
    return files;
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        const diffFile = process.argv[2];
        if (!diffFile) {
            const err = { error: 'Usage: node pr_scan.js <diff_file>' };
            console.log(JSON.stringify(err));
            process.exit(1);
        }
        const diff = (0, fs_1.readFileSync)(diffFile, 'utf8');
        const repo = process.env.SENTINEL_REPO || 'unknown';
        const prNumber = parseInt(process.env.SENTINEL_PR || '0', 10);
        const author = process.env.SENTINEL_AUTHOR || 'unknown';
        const files = parseUnifiedDiff(diff);
        const scanner = new lite_scanner_1.LiteScanner(new signal_vault_1.SignalVault());
        const result = yield scanner.auditPR(repo, prNumber, author, files);
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
            contentHash
        };
        console.log(JSON.stringify(output));
    });
}
main().catch(err => {
    console.log(JSON.stringify({ error: err.message }));
    process.exit(1);
});
