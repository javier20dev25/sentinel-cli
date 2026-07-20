import { describe, it, expect } from 'vitest';
import { buildScenarios, AttackScenario } from './attack_scenario';
import { GraphChain, GraphNode, EdgeType } from './agency_graph';
import { AgencyScoreResult } from './agency_score';

function node(subcode: string, category: string, riskScore = 70, contribution = 35): GraphNode {
  return {
    id: `${subcode}-file-1-0`,
    subcode,
    title: `${subcode} title`,
    severity: riskScore >= 70 ? 'CRITICAL' : riskScore >= 30 ? 'HIGH' : 'MEDIUM',
    riskScore,
    contribution,
    file: 'file.yml',
    line: 1,
    category,
    evidence: `${subcode} evidence`,
  };
}

function chain(nodes: GraphNode[], score?: number, confidence?: number): GraphChain {
  return {
    nodes,
    score: score ?? nodes.reduce((s, n) => s + n.riskScore, 0),
    confidence: confidence ?? 0.8,
  };
}

function makeAgency(score = 50): AgencyScoreResult {
  return {
    agencyScore: score,
    blastRadius: score >= 75 ? 'CRITICAL' as const : score >= 50 ? 'HIGH' as const : 'MEDIUM' as const,
    verdict: score >= 70 ? 'BLOCK' as const : score >= 30 ? 'REVIEW' as const : 'PASS' as const,
    drivers: [],
    totalFindings: 0,
    criticalCount: 0,
    highCount: 0,
  };
}

describe('buildScenarios', () => {
  it('returns empty array when no chains match', () => {
    const scenarios = buildScenarios([chain([node('SAST-EVAL', 'malware')])], makeAgency());
    expect(scenarios).toHaveLength(0);
  });

  it('matches SCE-001 Full Pipeline Takeover when all 4 categories present', () => {
    const c = chain([
      node('SEC-SLACK-TOKEN', 'secret'),
      node('TOK-004', 'token'),
      node('WF-007', 'workflow'),
      node('AS-001', 'agent'),
    ]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.length).toBeGreaterThanOrEqual(1);
    expect(scenarios[0].id).toBe('SCE-001');
    expect(scenarios[0].name).toBe('Full Pipeline Takeover');
    expect(scenarios[0].severity).toBe('CRITICAL');
    expect(scenarios[0].confidence).toBe(0.8);
  });

  it('matches SCE-002 Supply Chain Injection', () => {
    const c = chain([
      node('LIF-CURL-BASH', 'malware'),
      node('WF-001', 'workflow'),
    ]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.some(s => s.id === 'SCE-002')).toBe(true);
  });

  it('matches SCE-003 Secret-Driven Privilege Escalation', () => {
    const c = chain([
      node('SEC-AWS-ID', 'secret'),
      node('TOK-001', 'token'),
      node('WF-001', 'workflow'),
    ]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.some(s => s.id === 'SCE-003')).toBe(true);
  });

  it('matches SCE-004 Agent Policy Bypass via Workflow', () => {
    const c = chain([
      node('WF-002', 'workflow'),
      node('AS-003', 'agent'),
    ]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.some(s => s.id === 'SCE-004')).toBe(true);
  });

  it('matches SCE-005 PR Comment Injection', () => {
    const c = chain([
      node('WF-007', 'workflow'),
      node('AS-004', 'agent'),
    ]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.some(s => s.id === 'SCE-005')).toBe(true);
  });

  it('matches SCE-006 Credential Harvesting for short secret chains', () => {
    const c = chain([node('SEC-SSH-KEY', 'secret')]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.some(s => s.id === 'SCE-006')).toBe(true);
  });

  it('matches SCE-007 Obfuscated Payload Delivery', () => {
    const c = chain([
      node('OBF-PAYLOAD', 'malware'),
      node('LIF-OBFUSCATED', 'malware'),
    ]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.some(s => s.id === 'SCE-007')).toBe(true);
  });

  it('matches SCE-008 Workflow Self-Modification', () => {
    const c = chain([
      node('WF-004', 'workflow'),
      node('AS-001', 'agent'),
    ]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.some(s => s.id === 'SCE-008')).toBe(true);
  });

  it('matches SCE-009 Root Privilege Agent Escape', () => {
    const c = chain([
      node('WF-002', 'workflow'),
      node('AS-005', 'agent'),
    ]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.some(s => s.id === 'SCE-009')).toBe(true);
  });

  it('matches SCE-010 Dependency Confusion via Build Hooks', () => {
    const c = chain([node('GYP-SUBSTITUTION', 'malware')]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios.some(s => s.id === 'SCE-010')).toBe(true);
  });

  it('sorts scenarios by score descending', () => {
    const chains = [
      chain([node('WF-004', 'workflow'), node('AS-001', 'agent')], 80),
      chain([node('SEC-GITHUB-TOKEN', 'secret'), node('TOK-001', 'token'), node('WF-001', 'workflow'), node('AS-004', 'agent')], 95),
      chain([node('WF-007', 'workflow'), node('AS-004', 'agent')], 30),
    ];
    const scenarios = buildScenarios(chains, makeAgency());
    for (let i = 1; i < scenarios.length; i++) {
      expect(scenarios[i].score).toBeLessThanOrEqual(scenarios[i - 1].score);
    }
  });

  it('includes evidence strings for each node in the chain', () => {
    const c = chain([
      node('WF-002', 'workflow'),
      node('AS-005', 'agent'),
    ]);
    const scenarios = buildScenarios([c], makeAgency());
    expect(scenarios[0].evidence.length).toBe(2);
    expect(scenarios[0].evidence[0]).toContain('WF-002');
    expect(scenarios[0].evidence[1]).toContain('AS-005');
  });

  it('assigns severity based on score', () => {
    const high = buildScenarios([chain([node('WF-004', 'workflow'), node('AS-001', 'agent')], 45)], makeAgency());
    expect(high[0].severity).toBe('HIGH');

    const med = buildScenarios([chain([node('WF-007', 'workflow'), node('AS-004', 'agent')], 15)], makeAgency());
    expect(med[0].severity).toBe('MEDIUM');

    const critical = buildScenarios([chain([node('SEC-GITHUB-TOKEN', 'secret'), node('TOK-001', 'token'), node('WF-001', 'workflow'), node('AS-004', 'agent')], 85)], makeAgency());
    expect(critical[0].severity).toBe('CRITICAL');
  });
});
