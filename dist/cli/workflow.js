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
exports.prReview = prReview;
exports.fullAudit = fullAudit;
const child_process_1 = require("child_process");
const pr_audit_1 = require("./pr-audit");
function runGh(args) {
    var _a, _b;
    try {
        return (0, child_process_1.execFileSync)('gh', args, {
            timeout: 30000,
            encoding: 'utf-8',
            maxBuffer: 50 * 1024 * 1024,
            windowsHide: true,
        }).trim();
    }
    catch (e) {
        return ((_a = e.stdout) === null || _a === void 0 ? void 0 : _a.trim()) || ((_b = e.stderr) === null || _b === void 0 ? void 0 : _b.trim()) || e.message;
    }
}
function prReview(opts) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!opts.repo || !opts.prNumber) {
            console.error('Error: --repo and --pr are required for pr-review');
            process.exit(1);
        }
        const author = runGh(['pr', 'view', String(opts.prNumber), '--repo', opts.repo, '--json', 'author', '--jq', '.author.login']) || 'unknown';
        const result = yield (0, pr_audit_1.runPrAudit)({
            repo: opts.repo,
            prNumber: opts.prNumber,
            author,
            comment: opts.comment,
            checkRun: opts.checkRun,
        });
        console.log(JSON.stringify(result, null, 2));
        if (result.verdict.decision === 'BLOCK') {
            process.exit(1);
        }
    });
}
function fullAudit(opts) {
    return __awaiter(this, void 0, void 0, function* () {
        var _a;
        const repos = [];
        if (opts.repo) {
            repos.push(opts.repo);
            console.log(`Scanning repository: ${opts.repo}\n`);
        }
        else {
            const owner = opts.owner || 'javier20dev25';
            const reposRaw = runGh(['repo', 'list', owner, '--limit', '50', '--json', 'nameWithOwner']);
            try {
                const parsed = JSON.parse(reposRaw);
                for (const r of parsed) {
                    repos.push(r.nameWithOwner);
                }
            }
            catch (_b) {
                console.error('Failed to parse repo list');
                process.exit(1);
            }
            console.log(`Found ${repos.length} repositories. Scanning for open PRs...\n`);
        }
        let totalPRs = 0;
        let totalBlock = 0;
        let totalReview = 0;
        let totalPass = 0;
        const results = [];
        for (const repo of repos) {
            const prsRaw = runGh(['pr', 'list', '--repo', repo, '--state', 'open', '--json', 'number,title,author', '--limit', '20']);
            let prs = [];
            try {
                prs = JSON.parse(prsRaw);
            }
            catch (_c) {
                continue;
            }
            if (prs.length === 0)
                continue;
            console.log(`  ${repo} — ${prs.length} PR(s)`);
            for (const pr of prs) {
                totalPRs++;
                const result = yield (0, pr_audit_1.runPrAudit)({
                    repo,
                    prNumber: pr.number,
                    author: ((_a = pr.author) === null || _a === void 0 ? void 0 : _a.login) || 'unknown',
                    comment: opts.comment,
                    checkRun: opts.checkRun,
                });
                results.push({ repo, pr: pr.number, verdict: `${result.verdict.decision} [${result.verdict.band}]` });
                if (result.verdict.decision === 'BLOCK')
                    totalBlock++;
                else if (result.verdict.decision === 'REVIEW')
                    totalReview++;
                else
                    totalPass++;
            }
        }
        console.log(`\n====== FULL AUDIT SUMMARY ======`);
        console.log(`Total PRs scanned: ${totalPRs}`);
        console.log(`  BLOCK:  ${totalBlock}`);
        console.log(`  REVIEW: ${totalReview}`);
        console.log(`  PASS:   ${totalPass}`);
        console.log(`================================\n`);
        for (const r of results) {
            console.log(`  ${r.repo} #${r.pr} → ${r.verdict}`);
        }
    });
}
