"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PERMISSION_SCORES = void 0;
exports.calculateRiskScore = calculateRiskScore;
exports.classifyToken = classifyToken;
exports.extractTokenValue = extractTokenValue;
const CLASSIFIERS = [
    { test: t => /^github_pat_[0-9a-zA-Z]{22,}$/.test(t), type: 'GitHub Fine-grained PAT', provider: 'GitHub', baseScore: 30, confidence: 'high' },
    { test: t => /^ghp_[0-9a-zA-Z]{36}$/.test(t), type: 'GitHub Classic PAT', provider: 'GitHub', baseScore: 60, confidence: 'high' },
    { test: t => /^gho_[0-9a-zA-Z]{36}$/.test(t), type: 'GitHub OAuth Access Token', provider: 'GitHub', baseScore: 50, confidence: 'high' },
    { test: t => /^ghs_[0-9a-zA-Z]{36}$/.test(t), type: 'GitHub App Installation Token', provider: 'GitHub', baseScore: 15, confidence: 'high' },
    { test: t => /^ghu_[0-9a-zA-Z]{36}$/.test(t), type: 'GitHub User-to-Server Token', provider: 'GitHub', baseScore: 35, confidence: 'high' },
    { test: t => /^AKIA[0-9A-Z]{16}$/.test(t), type: 'AWS Access Key ID', provider: 'Amazon Web Services', baseScore: 80, confidence: 'high' },
    { test: t => /^sk_live_[0-9a-zA-Z]{24,}$/.test(t), type: 'Stripe Live Secret Key', provider: 'Stripe', baseScore: 80, confidence: 'high' },
    { test: t => /^pk_live_[0-9a-zA-Z]{24,}$/.test(t), type: 'Stripe Live Publishable Key', provider: 'Stripe', baseScore: 10, confidence: 'high' },
    { test: t => /^xoxb-[0-9a-zA-Z]{10,}$/.test(t), type: 'Slack Bot Token', provider: 'Slack', baseScore: 60, confidence: 'high' },
    { test: t => /^xoxa-[0-9a-zA-Z]{10,}$/.test(t), type: 'Slack App Token', provider: 'Slack', baseScore: 60, confidence: 'high' },
    { test: t => /^xoxp-[0-9a-zA-Z]{10,}$/.test(t), type: 'Slack User Token', provider: 'Slack', baseScore: 75, confidence: 'high' },
    { test: t => /^SG\.[A-Za-z0-9_-]{40,}$/.test(t), type: 'SendGrid API Key', provider: 'SendGrid', baseScore: 80, confidence: 'high' },
];
exports.PERMISSION_SCORES = {
    repo: 15,
    workflow: 10,
    'admin:org': 20,
    'contents:write': 15,
    'pull-requests:write': 10,
};
function getRiskLevel(score) {
    if (score >= 75)
        return 'critical';
    if (score >= 50)
        return 'high';
    if (score >= 25)
        return 'medium';
    return 'low';
}
function calculateRiskScore(baseScore, permissions) {
    let score = baseScore;
    if (permissions) {
        for (const perm of permissions) {
            score += exports.PERMISSION_SCORES[perm] || 0;
        }
    }
    return Math.max(0, Math.min(100, score));
}
function detectJWT(token) {
    return /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token);
}
function detectGenericSecret(token) {
    return token.length >= 16 && /^[A-Za-z0-9_\-\.]{16,}$/.test(token);
}
function classifyToken(token) {
    const trimmed = token.trim();
    for (const c of CLASSIFIERS) {
        if (c.test(trimmed)) {
            return {
                tokenType: c.type,
                provider: c.provider,
                riskScore: calculateRiskScore(c.baseScore),
                riskLevel: getRiskLevel(c.baseScore),
                confidence: c.confidence,
            };
        }
    }
    if (detectJWT(trimmed)) {
        return {
            tokenType: 'JWT (JSON Web Token)',
            provider: 'Unknown',
            riskScore: calculateRiskScore(45),
            riskLevel: getRiskLevel(45),
            confidence: 'medium',
        };
    }
    if (detectGenericSecret(trimmed)) {
        return {
            tokenType: 'Generic Secret / API Key',
            provider: 'Unknown',
            riskScore: calculateRiskScore(40),
            riskLevel: getRiskLevel(40),
            confidence: 'low',
        };
    }
    return {
        tokenType: 'Unknown',
        provider: 'Unknown',
        riskScore: 0,
        riskLevel: 'low',
        confidence: 'low',
    };
}
function extractTokenValue(snippet, secretType) {
    switch (secretType) {
        case 'SECRET_GITHUB_TOKEN': {
            const m = snippet.match(/gh[opsu]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22,}/);
            return m ? m[0] : null;
        }
        case 'SECRET_AWS_KEY_ID': {
            const m = snippet.match(/AKIA[0-9A-Z]{16}/);
            return m ? m[0] : null;
        }
        case 'SECRET_STRIPE_KEY': {
            const m = snippet.match(/sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}/);
            return m ? m[0] : null;
        }
        case 'SECRET_SENDGRID_KEY': {
            const m = snippet.match(/SG\.[A-Za-z0-9_-]{40,}/);
            return m ? m[0] : null;
        }
        case 'SECRET_SLACK_TOKEN': {
            const m = snippet.match(/xox[abp]\-[0-9a-zA-Z]{10,}/);
            return m ? m[0] : null;
        }
        default:
            return null;
    }
}
