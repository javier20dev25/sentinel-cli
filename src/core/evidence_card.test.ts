import { describe, it, expect } from 'vitest';
import { buildEvidenceCards, EvidenceCard } from './evidence_card';
import { calculateAgencyScore } from './agency_score';
import { LiteFinding } from './lite/lite_scanner';

function makeFinding(overrides: Partial<LiteFinding>): LiteFinding {
  return {
    type: 'SAST',
    subcode: 'SAST-001',
    category: 'injection',
    intent: 'malicious',
    file: 'test.js',
    line: 10,
    severity: 'HIGH',
    riskScore: 70,
    confidence: 'high',
    title: 'Test Finding',
    description: 'A test finding for evidence cards',
    evidence: 'Found suspicious code at test.js:10',
    snippet: 'eval(userInput)',
    ...overrides,
  };
}

describe('buildEvidenceCards', () => {
  it('returns empty array when no findings have riskScore', () => {
    const findings = [makeFinding({ riskScore: 0 }), makeFinding({ riskScore: undefined })];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    expect(cards).toHaveLength(0);
  });

  it('includes each finding as its own card (no dedup)', () => {
    const findings = [
      makeFinding({ subcode: 'WF-001', riskScore: 80 }),
      makeFinding({ subcode: 'WF-001', riskScore: 80, file: 'other.yml' }),
      makeFinding({ subcode: 'WF-002', riskScore: 50 }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    expect(cards).toHaveLength(3);
  });

  it('sorts by contribution descending', () => {
    const findings = [
      makeFinding({ subcode: 'WF-001', riskScore: 30 }),
      makeFinding({ subcode: 'WF-003', riskScore: 80 }),
      makeFinding({ subcode: 'WF-002', riskScore: 50 }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    for (let i = 1; i < cards.length; i++) {
      expect((cards[i].contribution || 0)).toBeLessThanOrEqual(cards[i - 1].contribution || 0);
    }
  });

  it('attaches contribution from agency driver', () => {
    const findings = [
      makeFinding({ subcode: 'WF-003', riskScore: 85 }),
      makeFinding({ subcode: 'WF-001', riskScore: 70 }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    for (const card of cards) {
      expect(card.contribution).toBeGreaterThan(0);
    }
  });

  it('includes subcode, title, category, severity, riskScore', () => {
    const findings = [
      makeFinding({
        subcode: 'SEC-AWS-ID',
        title: 'AWS Access Key',
        category: 'secrets',
        severity: 'CRITICAL',
        riskScore: 100,
      }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    expect(cards).toHaveLength(1);
    const card = cards[0];
    expect(card.subcode).toBe('SEC-AWS-ID');
    expect(card.title).toBe('AWS Access Key');
    expect(card.category).toBe('secrets');
    expect(card.severity).toBe('CRITICAL');
    expect(card.riskScore).toBe(100);
    expect(card.confidence).toBe('high');
  });

  it('includes file and line from finding', () => {
    const findings = [
      makeFinding({ file: 'deploy.yml', line: 12, subcode: 'WF-002', riskScore: 80 }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    expect(cards[0].file).toBe('deploy.yml');
    expect(cards[0].line).toBe(12);
  });

  it('includes evidence from finding evidence field', () => {
    const findings = [
      makeFinding({
        evidence: 'Found exposed AWS key in .env file',
        snippet: 'AWS_ACCESS_KEY_ID=AKIA...',
      }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    expect(cards[0].evidence).toBe('Found exposed AWS key in .env file');
  });

  it('falls back to snippet if evidence is missing', () => {
    const findings = [
      makeFinding({ evidence: undefined, snippet: 'eval(userInput)' }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    expect(cards[0].evidence).toBe('eval(userInput)');
  });

  it('attaches recommendation for known subcode', () => {
    const findings = [
      makeFinding({ subcode: 'WF-001', riskScore: 80 }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    expect(cards[0].recommendation).toBeDefined();
    expect(cards[0].recommendation).toContain('pull_request_target');
  });

  it('returns undefined recommendation for unknown subcode', () => {
    const findings = [
      makeFinding({ subcode: 'XXX-999', riskScore: 60 }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    expect(cards[0].recommendation).toBeUndefined();
  });

  it('renders multiple cards from diverse findings', () => {
    const findings = [
      makeFinding({ subcode: 'WF-001', riskScore: 80, category: 'workflow', severity: 'CRITICAL' }),
      makeFinding({ subcode: 'SEC-AWS-ID', riskScore: 100, category: 'secrets', severity: 'CRITICAL' }),
      makeFinding({ subcode: 'AS-001', riskScore: 50, category: 'agent-security', severity: 'HIGH' }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    expect(cards).toHaveLength(3);
    expect(cards[0].file).toBe('test.js');
    expect(cards[0].line).toBe(10);
  });
});
