import { describe, it, expect } from 'vitest';
import { computeDelta } from './pr_delta';
import { RiskSnapshot } from './risk_history';
import { LiteFinding } from './lite/lite_scanner';

function finding(subcode: string, file: string, line: number, severity = 'HIGH'): LiteFinding {
  return {
    type: subcode,
    subcode,
    category: 'generic',
    intent: 'test',
    file,
    line,
    severity,
    riskScore: 50,
    confidence: 'high',
    title: `${subcode} title`,
    description: `${subcode} description`,
    snippet: `${subcode} snippet`,
  };
}

function snapshot(findings: number): RiskSnapshot {
  return {
    id: 'test-snap',
    timestamp: new Date().toISOString(),
    agencyScore: 50,
    verdict: 'REVIEW',
    blastRadius: 'HIGH',
    totalFindings: findings,
    criticalCount: 1,
    highCount: 2,
    scenarioCount: 1,
    topScenarios: [],
    repoPath: '/test',
    repoHash: 'test123',
  };
}

describe('computeDelta', () => {
  it('identifies new findings', () => {
    const prev = [finding('WF-001', 'a.yml', 1)];
    const curr = [
      finding('WF-001', 'a.yml', 1),
      finding('AS-001', 'AGENTS.md', 5),
    ];
    const delta = computeDelta(curr, snapshot(1), prev);
    expect(delta.newFindings).toHaveLength(1);
    expect(delta.newFindings[0].subcode).toBe('AS-001');
    expect(delta.fixedFindings).toHaveLength(0);
  });

  it('identifies fixed findings', () => {
    const prev = [
      finding('WF-001', 'a.yml', 1),
      finding('AS-001', 'AGENTS.md', 5),
    ];
    const curr = [finding('WF-001', 'a.yml', 1)];
    const delta = computeDelta(curr, snapshot(2), prev);
    expect(delta.fixedFindings).toHaveLength(1);
    expect(delta.fixedFindings[0].subcode).toBe('AS-001');
    expect(delta.newFindings).toHaveLength(0);
  });

  it('identifies both new and fixed', () => {
    const prev = [finding('WF-001', 'a.yml', 1)];
    const curr = [finding('AS-001', 'AGENTS.md', 5)];
    const delta = computeDelta(curr, snapshot(1), prev);
    expect(delta.newFindings).toHaveLength(1);
    expect(delta.fixedFindings).toHaveLength(1);
  });

  it('handles empty previous findings', () => {
    const curr = [finding('WF-001', 'a.yml', 1)];
    const delta = computeDelta(curr, snapshot(0));
    expect(delta.newFindings).toHaveLength(1);
    expect(delta.fixedFindings).toHaveLength(0);
  });

  it('treats same subcode+file+line as same finding', () => {
    const prev = [finding('WF-001', 'a.yml', 5)];
    const curr = [finding('WF-001', 'a.yml', 5)];
    const delta = computeDelta(curr, snapshot(1), prev);
    expect(delta.newFindings).toHaveLength(0);
    expect(delta.fixedFindings).toHaveLength(0);
  });

  it('different line counts as different finding', () => {
    const prev = [finding('WF-001', 'a.yml', 5)];
    const curr = [finding('WF-001', 'a.yml', 10)];
    const delta = computeDelta(curr, snapshot(1), prev);
    expect(delta.newFindings).toHaveLength(1);
    expect(delta.fixedFindings).toHaveLength(1);
  });

  it('reports total counts', () => {
    const prev = [finding('WF-001', 'a.yml', 5)];
    const curr = [
      finding('WF-001', 'a.yml', 5),
      finding('AS-001', 'AGENTS.md', 10),
    ];
    const delta = computeDelta(curr, snapshot(1), prev);
    expect(delta.totalBefore).toBe(1);
    expect(delta.totalAfter).toBe(2);
  });
});
