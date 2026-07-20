import { describe, it, expect } from 'vitest';
import { buildAgencyGraph, EdgeType } from './agency_graph';
import { LiteFinding } from './lite/lite_scanner';
import { AgencyScoreResult } from './agency_score';

function makeFinding(overrides: Partial<LiteFinding>): LiteFinding {
  return {
    type: 'WORKFLOW_RISK',
    subcode: 'WF-001',
    category: 'workflow',
    intent: 'VULNERABILITY',
    file: '.github/workflows/deploy.yml',
    line: 5,
    severity: 'HIGH',
    riskScore: 70,
    confidence: 'high',
    title: 'pull_request_target trigger',
    description: 'WF-001 test',
    snippet: 'on: pull_request_target',
    ...overrides,
  };
}

function makeAgency(drivers: Array<{ subcode: string; contribution: number }>): AgencyScoreResult {
  return {
    agencyScore: drivers.reduce((s, d) => s + d.contribution, 0),
    blastRadius: 'MEDIUM',
    verdict: 'REVIEW',
    drivers: drivers.map(d => ({
      subcode: d.subcode,
      title: '',
      category: '',
      riskScore: d.contribution,
      contribution: d.contribution,
      confidence: 'high',
    })),
    totalFindings: drivers.length,
    criticalCount: 0,
    highCount: 0,
  };
}

describe('buildAgencyGraph', () => {
  it('returns empty graph when no findings have riskScore', () => {
    const agency = makeAgency([]);
    const graph = buildAgencyGraph([makeFinding({ riskScore: 0 })], agency);
    expect(graph.nodes).toHaveLength(0);
    expect(graph.chains).toHaveLength(0);
  });

  it('creates CAUSAL edge for semantic pair in same file', () => {
    const findings = [
      makeFinding({ subcode: 'TOK-001', riskScore: 70, category: 'token', file: 'same.yml' }),
      makeFinding({ subcode: 'WF-001', riskScore: 70, category: 'workflow', file: 'same.yml' }),
    ];
    const agency = makeAgency([{ subcode: 'TOK-001', contribution: 35 }, { subcode: 'WF-001', contribution: 35 }]);
    const graph = buildAgencyGraph(findings, agency);
    const causal = graph.edges.find(e => e.type === EdgeType.CAUSAL);
    expect(causal).toBeDefined();
    expect(causal!.confidence).toBe(0.9);
    expect(causal!.sourceId).toContain('TOK-001');
    expect(causal!.targetId).toContain('WF-001');
  });

  it('does NOT create CAUSAL edge across different files', () => {
    const findings = [
      makeFinding({ subcode: 'TOK-001', riskScore: 70, category: 'token', file: 'file-a.yml' }),
      makeFinding({ subcode: 'WF-001', riskScore: 70, category: 'workflow', file: 'file-b.yml' }),
    ];
    const agency = makeAgency([{ subcode: 'TOK-001', contribution: 35 }, { subcode: 'WF-001', contribution: 35 }]);
    const graph = buildAgencyGraph(findings, agency);
    const causal = graph.edges.find(e => e.type === EdgeType.CAUSAL);
    expect(causal).toBeUndefined();
  });

  it('uses contributions from Agency Score on nodes', () => {
    const findings = [
      makeFinding({ subcode: 'WF-002', riskScore: 85, category: 'workflow', file: 'same.yml' }),
    ];
    const agency = makeAgency([{ subcode: 'WF-002', contribution: 42 }]);
    const graph = buildAgencyGraph(findings, agency);
    expect(graph.nodes[0].contribution).toBe(42);
  });

  it('creates CORRELATED edge for same-file category progression', () => {
    const findings = [
      makeFinding({ subcode: 'SEC-AWS-ID', riskScore: 90, category: 'secret', file: '.env' }),
      makeFinding({ subcode: 'WF-002', riskScore: 85, category: 'workflow', file: '.env' }),
    ];
    const agency = makeAgency([
      { subcode: 'SEC-AWS-ID', contribution: 45 },
      { subcode: 'WF-002', contribution: 42 },
    ]);
    const graph = buildAgencyGraph(findings, agency);
    const correlated = graph.edges.find(e => e.type === EdgeType.CORRELATED);
    expect(correlated).toBeDefined();
    expect(correlated!.confidence).toBe(0.5);
  });

  it('builds a full chain: SEC→TOK→WF→AS in same file', () => {
    const findings = [
      makeFinding({ subcode: 'SEC-GITHUB-TOKEN', riskScore: 90, category: 'secret', file: 'chain.yml' }),
      makeFinding({ subcode: 'TOK-001', riskScore: 70, category: 'token', file: 'chain.yml' }),
      makeFinding({ subcode: 'WF-001', riskScore: 70, category: 'workflow', file: 'chain.yml' }),
      makeFinding({ subcode: 'AS-004', riskScore: 70, category: 'agent', file: 'chain.yml' }),
    ];
    const agency = makeAgency([
      { subcode: 'SEC-GITHUB-TOKEN', contribution: 45 },
      { subcode: 'TOK-001', contribution: 35 },
      { subcode: 'WF-001', contribution: 17 },
      { subcode: 'AS-004', contribution: 8 },
    ]);
    const graph = buildAgencyGraph(findings, agency);
    const fullChain = graph.chains.find(c => c.nodes.length >= 4);
    expect(fullChain).toBeDefined();
    expect(fullChain!.nodes[0].subcode).toBe('SEC-GITHUB-TOKEN');
    expect(fullChain!.nodes[fullChain!.nodes.length - 1].subcode).toBe('AS-004');
    expect(fullChain!.score).toBeGreaterThan(0);
    expect(fullChain!.confidence).toBeGreaterThan(0);
  });

  it('chain score uses maxRiskScore × pathConfidence × lengthFactor', () => {
    const findings = [
      makeFinding({ subcode: 'SEC-GITHUB-TOKEN', riskScore: 90, category: 'secret', file: 'chain.yml' }),
      makeFinding({ subcode: 'TOK-001', riskScore: 70, category: 'token', file: 'chain.yml' }),
    ];
    const agency = makeAgency([
      { subcode: 'SEC-GITHUB-TOKEN', contribution: 45 },
      { subcode: 'TOK-001', contribution: 35 },
    ]);
    const graph = buildAgencyGraph(findings, agency);
    expect(graph.chains.length).toBeGreaterThanOrEqual(1);
    for (const chain of graph.chains) {
      expect(chain.score).toBeGreaterThan(0);
      expect(chain.score).toBeLessThanOrEqual(100);
      expect(chain.confidence).toBeGreaterThan(0);
      expect(chain.confidence).toBeLessThanOrEqual(1);
    }
  });

  it('allows same node to participate in multiple chains (no destructive visited)', () => {
    // TOK-001 connects to both WF-001 (CAUSAL) and WF-005 (CORRELATED via file order).
    // WF-001 and WF-005 are different subcodes so both connections form valid chains.
    const findings = [
      makeFinding({ subcode: 'TOK-001', riskScore: 70, category: 'token', file: 'multi.yml' }),
      makeFinding({ subcode: 'WF-001', riskScore: 70, category: 'workflow', file: 'multi.yml' }),
      makeFinding({ subcode: 'WF-005', riskScore: 85, category: 'workflow', file: 'multi.yml' }),
    ];
    const agency = makeAgency([
      { subcode: 'TOK-001', contribution: 35 },
      { subcode: 'WF-001', contribution: 17 },
      { subcode: 'WF-005', contribution: 21 },
    ]);
    const graph = buildAgencyGraph(findings, agency);
    // Should find at least 2 chains starting from TOK-001
    const tokStarts = graph.chains.filter(c => c.nodes[0]?.subcode === 'TOK-001');
    expect(tokStarts.length).toBeGreaterThanOrEqual(2);
  });

  it('sorts chains by score desc, then confidence desc', () => {
    const findings = [
      makeFinding({ subcode: 'TOK-001', riskScore: 70, category: 'token', file: 'sort.yml' }),
      makeFinding({ subcode: 'WF-001', riskScore: 70, category: 'workflow', file: 'sort.yml' }),
      makeFinding({ subcode: 'SEC-GITHUB-TOKEN', riskScore: 90, category: 'secret', file: 'sort.yml' }),
    ];
    const agency = makeAgency([
      { subcode: 'TOK-001', contribution: 35 },
      { subcode: 'SEC-GITHUB-TOKEN', contribution: 45 },
      { subcode: 'WF-001', contribution: 17 },
    ]);
    const graph = buildAgencyGraph(findings, agency);
    for (let i = 1; i < graph.chains.length; i++) {
      expect(graph.chains[i].score).toBeLessThanOrEqual(graph.chains[i - 1].score);
    }
  });

  it('includes edge type and confidence on every edge', () => {
    const findings = [
      makeFinding({ subcode: 'TOK-001', riskScore: 70, category: 'token', file: 'types.yml' }),
      makeFinding({ subcode: 'WF-001', riskScore: 70, category: 'workflow', file: 'types.yml' }),
    ];
    const agency = makeAgency([
      { subcode: 'TOK-001', contribution: 35 },
      { subcode: 'WF-001', contribution: 17 },
    ]);
    const graph = buildAgencyGraph(findings, agency);
    expect(graph.edges.length).toBeGreaterThanOrEqual(1);
    for (const edge of graph.edges) {
      expect([EdgeType.CAUSAL, EdgeType.CORRELATED, EdgeType.SAME_FILE]).toContain(edge.type);
      expect(edge.confidence).toBeGreaterThan(0);
      expect(edge.confidence).toBeLessThanOrEqual(1);
    }
  });
});
