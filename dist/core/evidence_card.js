"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildEvidenceCards = buildEvidenceCards;
const RECOMMENDATIONS = {
    'WF-001': 'Replace pull_request_target with pull_request and restrict permissions, or audit fork PRs manually.',
    'WF-002': 'Use granular permissions instead of write-all. List only the scopes the workflow needs.',
    'WF-003': 'Remove contents:write unless the workflow needs to push tags or releases.',
    'WF-004': 'Prevent workflow steps from writing to .github/workflows/. Use read-only filesystem.',
    'WF-005': 'Avoid piping remote downloads to shell. Use actions/download-artifact or checksum verification.',
    'WF-006': 'Set persist-credentials: false and use explicit GITHUB_TOKEN or OIDC tokens per step.',
    'WF-007': 'Comment-triggered workflows should not have write permissions or checkout PR code.',
    'AS-001': 'Remove instructions that disable or bypass Sentinel. Security controls must remain active.',
    'AS-002': 'Restrict file write permissions to specific directories. Avoid unrestricted write access.',
    'AS-003': 'Require human validation before executing commands. Remove auto-approve instructions.',
    'AS-004': 'Never allow agents to commit or push without human review. Always require PR + approval.',
    'AS-005': 'Remove root or sudo access from agent instructions. Use least-privilege principle.',
    'AS-006': 'Do not skip CI or code review. All merges require passing checks and approval.',
    'AS-007': 'Avoid MCP filesystem, write, or exec capabilities. Prefer read-only MCP servers.',
    'AS-008': 'Security policies and restrictions must not be overridable by agent instructions.',
    'SEC-AWS-ID': 'Rotate the AWS Access Key immediately. Check IAM policies for excessive permissions.',
    'SEC-AWS-SECRET': 'Rotate immediately. This secret key grants full API access tied to the access key ID.',
    'SEC-GITHUB-TOKEN': 'Rotate immediately. If classic PAT, replace with fine-grained PAT limited to specific repos.',
    'SEC-STRIPE': 'Rotate from Stripe Dashboard immediately. Check for unauthorized charges.',
    'SEC-SENDGRID': 'Rotate from SendGrid Dashboard immediately. Check email logs for abuse.',
    'SEC-SLACK-TOKEN': 'Rotate immediately. Review token scopes and revoke if no longer needed.',
    'SEC-SSH-KEY': 'Rotate immediately. Remove the key from authorized_keys and deploy a new one.',
    'TOK-001': 'Remove contents:write or replace GITHUB_TOKEN with a fine-grained token with read-only access.',
    'TOK-002': 'Remove actions:write or restrict workflow modification to trusted workflows only.',
    'TOK-003': 'Remove pull-requests:write or use read-only token for PR operations.',
    'TOK-004': 'Avoid pull_request_target with write permissions. Use pull_request with read-only token.',
    'LIF-CURL-BASH': 'Remove curl|bash from lifecycle scripts. Pin exact package versions.',
};
function buildEvidenceCards(findings, agencyResult) {
    const driverMap = new Map();
    for (const d of agencyResult.drivers) {
        driverMap.set(d.subcode, d);
    }
    const cards = [];
    for (const f of findings) {
        if (!f.riskScore || f.riskScore === 0)
            continue;
        const subcode = f.subcode || '';
        const driver = driverMap.get(subcode);
        cards.push({
            subcode,
            title: f.title || '',
            category: f.category || 'generic',
            severity: f.severity,
            riskScore: f.riskScore,
            confidence: f.confidence || 'high',
            file: f.file,
            line: f.line,
            evidence: f.evidence || f.snippet.substring(0, 120) || undefined,
            description: f.description,
            contribution: driver === null || driver === void 0 ? void 0 : driver.contribution,
            recommendation: RECOMMENDATIONS[subcode],
        });
    }
    // Sort by contribution descending (with contribution 0 at end)
    cards.sort((a, b) => (b.contribution || 0) - (a.contribution || 0));
    return cards;
}
