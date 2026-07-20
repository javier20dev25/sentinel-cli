import { describe, it, expect } from 'vitest';
import { buildEvidencePacks, EvidencePack } from './evidence_pack';
import { buildScenarios, AttackScenario } from './attack_scenario';
import { buildAgencyGraph, GraphChain, GraphNode, AgencyGraph, EdgeType } from './agency_graph';
import { AgencyScoreResult, AgencyDriver } from './agency_score';
import { LiteFinding } from './lite/lite_scanner';
import { EvidenceCard } from './evidence_card';

function node(subcode: string, category: string, riskScore = 70, contribution = 35, file = 'file.yml', line = 1): GraphNode {
  return {
    id: `${subcode}-${file}-${line}-0`,
    subcode,
    title: `${subcode} title`,
    severity: riskScore >= 70 ? 'CRITICAL' : riskScore >= 30 ? 'HIGH' : 'MEDIUM',
    riskScore,
    contribution,
    file,
    line,
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

function toGraph(chains: GraphChain[]): AgencyGraph {
  const nodes = chains.flatMap(c => c.nodes);
  const edges: any[] = [];
  for (const c of chains) {
    for (let i = 0; i < c.nodes.length - 1; i++) {
      edges.push({
        sourceId: c.nodes[i].id,
        targetId: c.nodes[i + 1].id,
        type: EdgeType.CAUSAL,
        confidence: 0.9,
        label: `${c.nodes[i].subcode}→${c.nodes[i + 1].subcode}`,
      });
    }
  }
  return { nodes, edges, chains };
}

describe('buildEvidencePacks', () => {
  it('returns empty array when no scenarios', () => {
    const packs = buildEvidencePacks([], { nodes: [], edges: [], chains: [] }, [], [], makeAgency());
    expect(packs).toHaveLength(0);
  });

  it('creates a pack for each scenario', () => {
    const c = chain([
      node('WF-004', 'workflow'),
      node('AS-001', 'agent'),
    ], 80, 0.9);
    const graph = toGraph([c]);
    const scenarios = buildScenarios(graph.chains, makeAgency());
    const packs = buildEvidencePacks(scenarios, graph, [], [], makeAgency());
    expect(packs.length).toBeGreaterThanOrEqual(1);
    expect(packs[0].id).toBe('SCE-008');
    expect(packs[0].title).toBe('Workflow Self-Modification');
  });

  it('includes affected assets from chain nodes', () => {
    const n1 = node('WF-004', 'workflow', 70, 35, 'build.yml');
    const n2 = node('AS-001', 'agent', 80, 40, 'AGENTS.md');
    const c = chain([n1, n2], 80, 0.9);
    const graph = toGraph([c]);
    const scenarios = buildScenarios(graph.chains, makeAgency());
    const packs = buildEvidencePacks(scenarios, graph, [], [], makeAgency());
    expect(packs[0].affectedAssets).toContain('AGENTS.md');
    expect(packs[0].affectedAssets).toContain('build.yml');
  });

  it('includes evidence items with subcode and file details', () => {
    const n1 = node('WF-004', 'workflow', 70, 35, 'build.yml', 5);
    const n2 = node('AS-001', 'agent', 80, 40, 'AGENTS.md', 10);
    const c = chain([n1, n2], 80, 0.9);
    const graph = toGraph([c]);
    const scenarios = buildScenarios(graph.chains, makeAgency());
    const packs = buildEvidencePacks(scenarios, graph, [], [], makeAgency());
    expect(packs[0].evidenceItems.length).toBe(2);
    expect(packs[0].evidenceItems[0].subcode).toBe('WF-004');
    expect(packs[0].evidenceItems[0].file).toBe('build.yml');
    expect(packs[0].evidenceItems[0].line).toBe(5);
    expect(packs[0].evidenceItems[1].subcode).toBe('AS-001');
    expect(packs[0].evidenceItems[1].file).toBe('AGENTS.md');
    expect(packs[0].evidenceItems[1].line).toBe(10);
  });

  it('includes narrative with description from scenario', () => {
    const c = chain([
      node('WF-004', 'workflow'),
      node('AS-001', 'agent'),
    ], 80, 0.9);
    const graph = toGraph([c]);
    const scenarios = buildScenarios(graph.chains, makeAgency());
    const packs = buildEvidencePacks(scenarios, graph, [], [], makeAgency());
    expect(packs[0].narrative).toBeTruthy();
    expect(packs[0].narrative.length).toBeGreaterThan(10);
  });

  it('includes impact from scenario', () => {
    const c = chain([
      node('WF-004', 'workflow'),
      node('AS-001', 'agent'),
    ], 80, 0.9);
    const graph = toGraph([c]);
    const scenarios = buildScenarios(graph.chains, makeAgency());
    const packs = buildEvidencePacks(scenarios, graph, [], [], makeAgency());
    expect(packs[0].impact).toBeTruthy();
    expect(packs[0].impact).toContain('CI/CD');
  });

  it('includes remediation steps from evidence cards', () => {
    const n1 = node('WF-004', 'workflow', 70, 35, 'build.yml');
    const n2 = node('AS-001', 'agent', 80, 40, 'AGENTS.md');
    const c = chain([n1, n2], 80, 0.9);
    const graph = toGraph([c]);
    const scenarios = buildScenarios(graph.chains, makeAgency());
    const cards: EvidenceCard[] = [
      {
        subcode: 'WF-004',
        title: 'Workflow Modifies Workflow Files',
        category: 'workflow',
        severity: 'CRITICAL',
        riskScore: 70,
        confidence: 'high',
        file: 'build.yml',
        line: 5,
        description: 'Workflow can modify workflow files',
        contribution: 35,
        recommendation: 'Prevent workflow steps from writing to .github/workflows/.',
      },
      {
        subcode: 'AS-001',
        title: 'Bypass Sentinel',
        category: 'agent',
        severity: 'CRITICAL',
        riskScore: 80,
        confidence: 'high',
        file: 'AGENTS.md',
        line: 10,
        description: 'Instructions disable Sentinel',
        contribution: 40,
        recommendation: 'Remove instructions that disable Sentinel.',
      },
    ];
    const packs = buildEvidencePacks(scenarios, graph, [], cards, makeAgency());
    expect(packs[0].remediationSteps.length).toBeGreaterThanOrEqual(2);
    expect(packs[0].remediationSteps.some(s => s.includes('WF-004'))).toBe(true);
    expect(packs[0].remediationSteps.some(s => s.includes('AS-001'))).toBe(true);
  });

  it('sorts packs by score descending', () => {
    const c1 = chain([
      node('WF-007', 'workflow', 30, 15),
      node('AS-004', 'agent', 40, 20),
    ], 30, 0.7);
    const c2 = chain([
      node('WF-004', 'workflow', 70, 35),
      node('AS-001', 'agent', 80, 40),
    ], 80, 0.9);
    const graph = toGraph([c1, c2]);
    const scenarios = buildScenarios(graph.chains, makeAgency());
    const packs = buildEvidencePacks(scenarios, graph, [], [], makeAgency());
    for (let i = 1; i < packs.length; i++) {
      expect(packs[i].score).toBeLessThanOrEqual(packs[i - 1].score);
    }
  });

  it('reports chain length in pack', () => {
    const c = chain([
      node('SEC-AWS-ID', 'secret'),
      node('TOK-001', 'token'),
      node('WF-001', 'workflow'),
    ], 85, 0.9);
    const graph = toGraph([c]);
    const scenarios = buildScenarios(graph.chains, makeAgency());
    const packs = buildEvidencePacks(scenarios, graph, [], [], makeAgency());
    expect(packs[0].chainLength).toBe(3);
  });

  it('handles Full Pipeline Takeover pack', () => {
    const c = chain([
      node('SEC-GITHUB-TOKEN', 'secret'),
      node('TOK-004', 'token'),
      node('WF-007', 'workflow'),
      node('AS-001', 'agent'),
    ], 95, 0.95);
    const graph = toGraph([c]);
    const scenarios = buildScenarios(graph.chains, makeAgency());
    const packs = buildEvidencePacks(scenarios, graph, [], [], makeAgency());
    const ftp = packs.find(p => p.id === 'SCE-001');
    expect(ftp).toBeDefined();
    expect(ftp!.title).toBe('Full Pipeline Takeover');
    expect(ftp!.severity).toBe('CRITICAL');
    expect(ftp!.chainLength).toBe(4);
  });
});
