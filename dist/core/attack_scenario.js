"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildScenarios = buildScenarios;
const MATCHERS = [
    // Most specific matchers first (checked by explicit subcode)
    {
        id: 'SCE-005',
        name: 'Pull Request Comment Injection',
        description: 'Comment-triggered workflows combined with agent instructions to skip review allow PR comment injection attacks.',
        impact: 'Unauthorized code changes triggered by issue or PR comments, bypassing code review gates.',
        matchChain: (c) => hasAny(c, ['WF-007']) && hasAny(c, ['AS-003', 'AS-004']),
    },
    {
        id: 'SCE-008',
        name: 'Workflow Self-Modification',
        description: 'A workflow can modify its own workflow files, enabling persistent compromise of the CI/CD pipeline.',
        impact: 'Persistent CI/CD compromise: workflow files can be altered to inject malicious steps, exfiltrate secrets, or disable security checks.',
        matchChain: (c) => hasAny(c, ['WF-004']) && hasAny(c, ['AS-001', 'AS-008']),
    },
    {
        id: 'SCE-009',
        name: 'Root Privilege Agent Escape',
        description: 'Workflow write-all permissions combined with agent instructions granting root access enable full system compromise.',
        impact: 'Complete system compromise: agent running with root privileges can modify system files, install malware, and persist across reboots.',
        matchChain: (c) => hasAny(c, ['WF-002']) && hasAny(c, ['AS-005']),
    },
    // Mid-specificity matchers
    {
        id: 'SCE-002',
        name: 'Supply Chain Injection',
        description: 'Suspicious lifecycle scripts or build hooks in combination with workflow manipulation enable supply chain compromise.',
        impact: 'Malicious code execution at install time, dependency confusion, downstream consumer compromise.',
        matchChain: (c) => hasAny(c, ['LIF-CURL-BASH', 'LIF-SHELL', 'LIF-OBFUSCATED', 'GYP-SUBSTITUTION', 'GYP-DOWNLOADER'])
            && hasAny(c, ['WF-001', 'WF-002', 'WF-003', 'WF-004']),
    },
    {
        id: 'SCE-003',
        name: 'Secret-Driven Privilege Escalation',
        description: 'Exposed secrets grant excessive workflow permissions, enabling unauthorized operations in CI/CD.',
        impact: 'Privilege escalation via leaked credentials: unauthorized push, release modification, environment variable access.',
        matchChain: (c) => hasCategory(c, 'secret') && hasAny(c, ['TOK-001', 'TOK-002', 'TOK-003'])
            && hasAny(c, ['WF-001', 'WF-002', 'WF-003', 'WF-007']),
    },
    {
        id: 'SCE-001',
        name: 'Full Pipeline Takeover',
        description: 'An exposed credential enables workflow modification, which allows an AI agent to bypass security controls.',
        impact: 'Complete CI/CD pipeline compromise: security controls bypass, repository persistence, malicious code insertion.',
        matchChain: (c) => hasAll(c, ['secret', 'token', 'workflow', 'agent']),
    },
    {
        id: 'SCE-007',
        name: 'Obfuscated Payload Delivery',
        description: 'Obfuscated code in lifecycle scripts enables payload delivery at package install time, bypassing static analysis.',
        impact: 'Silent compromise at npm install: arbitrary code execution, credential exfiltration, backdoor installation.',
        matchChain: (c) => hasAny(c, ['OBF-PAYLOAD']) && hasAny(c, ['LIF-CURL-BASH', 'LIF-SHELL', 'LIF-OBFUSCATED']),
    },
    // Generic category matchers last
    {
        id: 'SCE-004',
        name: 'Agent Policy Bypass via Workflow',
        description: 'Workflow vulnerabilities enable AI agent instructions to bypass security reviews and guards.',
        impact: 'AI agent can commit, push, and deploy without human review, override security policies, and execute arbitrary commands.',
        matchChain: (c) => hasCategory(c, 'workflow') && hasCategory(c, 'agent'),
    },
    {
        id: 'SCE-010',
        name: 'Dependency Confusion via Build Hooks',
        description: 'GYP build files with command substitution enable arbitrary code execution at install time.',
        impact: 'Supply chain attack via native addon build: arbitrary code execution during npm install, potential for cross-platform compromise.',
        matchChain: (c) => hasAny(c, ['GYP-SUBSTITUTION', 'GYP-DOWNLOADER', 'GYP-FILE']),
    },
    {
        id: 'SCE-006',
        name: 'Credential Harvesting',
        description: 'Plaintext credentials or secrets exposed in the repository, accessible to anyone with read access.',
        impact: 'Immediate credential rotation required. Risk of unauthorized access to cloud services, CI/CD, or third-party APIs.',
        matchChain: (c) => hasCategory(c, 'secret') && c.nodes.length <= 2,
    },
];
function hasAny(chain, subcodes) {
    return chain.nodes.some(n => subcodes.includes(n.subcode));
}
function hasAll(chain, categories) {
    const cats = new Set(chain.nodes.map(n => n.category));
    return categories.every(c => cats.has(c));
}
function hasCategory(chain, category) {
    return chain.nodes.some(n => n.category === category);
}
function buildScenarios(chains, agency) {
    const scenarios = [];
    const usedChainIds = new Set();
    // Order chains by score desc for best-first matching
    const sorted = [...chains].sort((a, b) => b.score - a.score);
    for (const chain of sorted) {
        for (const matcher of MATCHERS) {
            if (matcher.matchChain(chain)) {
                const key = chain.nodes.map(n => n.id).join('|') + '|' + matcher.id;
                if (usedChainIds.has(hashStr(key)))
                    continue;
                usedChainIds.add(hashStr(key));
                const sev = chain.score >= 70 ? 'CRITICAL'
                    : chain.score >= 30 ? 'HIGH'
                        : chain.score >= 10 ? 'MEDIUM'
                            : 'LOW';
                const evidence = chain.nodes.map(n => {
                    const loc = `${n.file}:${n.line}`;
                    return `${n.subcode}: ${n.title} (${loc}) — score ${n.riskScore}, contribution +${n.contribution}`;
                });
                scenarios.push({
                    id: matcher.id,
                    name: matcher.name,
                    description: matcher.description,
                    impact: matcher.impact,
                    severity: sev,
                    score: chain.score,
                    confidence: chain.confidence,
                    evidence,
                    chain,
                });
                break; // first matching scenario per chain
            }
        }
    }
    // Sort by score descending
    scenarios.sort((a, b) => b.score - a.score);
    return scenarios;
}
function hashStr(s) {
    let hash = 0;
    for (let i = 0; i < s.length; i++) {
        hash = ((hash << 5) - hash) + s.charCodeAt(i);
        hash |= 0;
    }
    return hash;
}
