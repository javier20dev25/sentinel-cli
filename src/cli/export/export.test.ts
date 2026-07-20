import { describe, it, expect } from 'vitest';
import { renderEnrichedJson } from './json';
import { renderSarif } from './sarif';
import { renderMarkdown } from './markdown';
import { evaluatePolicy, PolicyOptions } from './policy';
import { calculateAgencyScore, AgencyScoreResult } from '../../core/agency_score';
import { buildEvidenceCards } from '../../core/evidence_card';
import { LiteFinding } from '../../core/lite/lite_scanner';

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
    description: 'A test finding',
    evidence: 'Found suspicious code',
    snippet: 'eval(userInput)',
    ...overrides,
  };
}

const meta = { host: 'test-machine', scanTimeMs: 150, memoryMB: 42 };

describe('renderEnrichedJson', () => {
  it('includes agency score and cards in output', () => {
    const findings = [makeFinding({})];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const json = renderEnrichedJson(findings, agency, cards, meta);
    const parsed = JSON.parse(json);
    expect(parsed.agencyScore).toBeGreaterThanOrEqual(0);
    expect(parsed.verdict).toBeDefined();
    expect(parsed.blastRadius).toBeDefined();
    expect(parsed.drivers).toBeInstanceOf(Array);
    expect(parsed.cards).toBeInstanceOf(Array);
    expect(parsed.cards[0].file).toBe('test.js');
    expect(parsed.cards[0].line).toBe(10);
  });

  it('includes host, scanTimeMs, memoryMB metadata', () => {
    const findings: LiteFinding[] = [];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const json = renderEnrichedJson(findings, agency, cards, meta);
    const parsed = JSON.parse(json);
    expect(parsed.host).toBe('test-machine');
    expect(parsed.scanTimeMs).toBe(150);
    expect(parsed.memoryMB).toBe(42);
  });

  it('is valid JSON', () => {
    const findings = [
      makeFinding({ subcode: 'WF-001', riskScore: 80 }),
      makeFinding({ subcode: 'AS-001', riskScore: 50 }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const json = renderEnrichedJson(findings, agency, cards, meta);
    expect(() => JSON.parse(json)).not.toThrow();
  });
});

describe('renderSarif', () => {
  it('produces valid SARIF 2.1.0 JSON', () => {
    const findings = [makeFinding({})];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const sarif = renderSarif(findings, agency, cards);
    const parsed = JSON.parse(sarif);
    expect(parsed.$schema).toContain('sarif-schema-2.1.0');
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toBeInstanceOf(Array);
    expect(parsed.runs).toHaveLength(1);
  });

  it('includes tool with driver and rules', () => {
    const findings = [makeFinding({})];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const sarif = renderSarif(findings, agency, cards);
    const parsed = JSON.parse(sarif);
    const run = parsed.runs[0];
    expect(run.tool.driver.name).toBe('Sentinel');
    expect(run.tool.driver.rules).toBeInstanceOf(Array);
    expect(run.tool.driver.rules.length).toBeGreaterThanOrEqual(1);
  });

  it('includes results with locations', () => {
    const findings = [makeFinding({ file: 'src/app.js', line: 42 })];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const sarif = renderSarif(findings, agency, cards);
    const parsed = JSON.parse(sarif);
    const results = parsed.runs[0].results;
    expect(results).toHaveLength(1);
    expect(results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/app.js');
    expect(results[0].locations[0].physicalLocation.region.startLine).toBe(42);
  });

  it('maps severity to SARIF level', () => {
    const findings = [
      makeFinding({ severity: 'CRITICAL', subcode: 'SEC-001' }),
      makeFinding({ severity: 'MEDIUM', subcode: 'WF-001', riskScore: 30 }),
    ];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const sarif = renderSarif(findings, agency, cards);
    const parsed = JSON.parse(sarif);
    const results = parsed.runs[0].results;
    expect(results[0].level).toBe('error');
    expect(results[1].level).toBe('warning');
  });

  it('includes properties on run level', () => {
    const findings = [makeFinding({ riskScore: 80 })];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const sarif = renderSarif(findings, agency, cards);
    const parsed = JSON.parse(sarif);
    const props = parsed.runs[0].properties;
    expect(props.agencyScore).toBeGreaterThanOrEqual(0);
    expect(props.verdict).toBeDefined();
    expect(props.evidenceCards).toBeInstanceOf(Array);
    expect(props.drivers).toBeInstanceOf(Array);
  });
});

describe('renderMarkdown', () => {
  it('includes table with agency score, verdict, blast radius', () => {
    const findings = [makeFinding({ riskScore: 85 })];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const md = renderMarkdown(findings.length, agency, cards);
    expect(md).toContain('Agency Score');
    expect(md).toContain('Verdict');
    expect(md).toContain('Blast Radius');
    expect(md).toContain('Critical');
    expect(md).toContain('High');
    expect(md).toContain('---');
  });

  it('includes drivers table when drivers exist', () => {
    const findings = [makeFinding({ subcode: 'WF-003', riskScore: 80 })];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const md = renderMarkdown(findings.length, agency, cards);
    expect(md).toContain('Top Drivers');
    expect(md).toContain('WF-003');
  });

  it('includes evidence cards section with details tags', () => {
    const findings = [makeFinding({ subcode: 'AS-001', riskScore: 60 })];
    const agency = calculateAgencyScore(findings);
    const cards = buildEvidenceCards(findings, agency);
    const md = renderMarkdown(findings.length, agency, cards);
    expect(md).toContain('Evidence Cards');
    expect(md).toContain('<details>');
    expect(md).toContain('</details>');
    expect(md).toContain('AS-001');
  });
});

describe('evaluatePolicy', () => {
  const makeAgency = (score: number, verdict: 'PASS' | 'REVIEW' | 'BLOCK' = 'PASS'): AgencyScoreResult => ({
    agencyScore: score,
    blastRadius: score >= 75 ? 'CRITICAL' as const : score >= 50 ? 'HIGH' as const : 'LOW' as const,
    verdict,
    drivers: [],
    totalFindings: 0,
    criticalCount: 0,
    highCount: 0,
  });

  it('no policy → no fail', () => {
    const result = evaluatePolicy([], makeAgency(90), {});
    expect(result.shouldFail).toBe(false);
  });

  describe('failOnScore', () => {
    it('returns no fail when threshold is undefined', () => {
      const result = evaluatePolicy([], makeAgency(90), { failOnScore: undefined });
      expect(result.shouldFail).toBe(false);
    });

    it('returns no fail when score is below threshold', () => {
      const result = evaluatePolicy([], makeAgency(30), { failOnScore: 70 });
      expect(result.shouldFail).toBe(false);
    });

    it('returns fail when score equals threshold', () => {
      const result = evaluatePolicy([], makeAgency(70), { failOnScore: 70 });
      expect(result.shouldFail).toBe(true);
    });

    it('returns fail when score exceeds threshold', () => {
      const result = evaluatePolicy([], makeAgency(85), { failOnScore: 50 });
      expect(result.shouldFail).toBe(true);
    });

    it('ignores invalid threshold values', () => {
      const result = evaluatePolicy([], makeAgency(50), { failOnScore: -1 });
      expect(result.shouldFail).toBe(false);
    });
  });

  describe('failOnCritical', () => {
    it('returns no fail when no CRITICAL findings', () => {
      const findings = [makeFinding({ severity: 'HIGH' })];
      const result = evaluatePolicy(findings, makeAgency(50), { failOnCritical: true });
      expect(result.shouldFail).toBe(false);
    });

    it('returns fail when CRITICAL findings exist', () => {
      const findings = [
        makeFinding({ severity: 'CRITICAL', subcode: 'SEC-001' }),
        makeFinding({ severity: 'HIGH' }),
      ];
      const result = evaluatePolicy(findings, makeAgency(80), { failOnCritical: true });
      expect(result.shouldFail).toBe(true);
      expect(result.reason).toContain('CRITICAL');
      expect(result.reason).toContain('SEC-001');
    });

    it('returns fail with multiple CRITICAL subcodes', () => {
      const findings = [
        makeFinding({ severity: 'CRITICAL', subcode: 'SEC-001' }),
        makeFinding({ severity: 'CRITICAL', subcode: 'WF-003', riskScore: 90 }),
      ];
      const result = evaluatePolicy(findings, makeAgency(90), { failOnCritical: true });
      expect(result.shouldFail).toBe(true);
    });
  });

  describe('failOnHigh', () => {
    it('returns no fail when no HIGH findings', () => {
      const findings = [makeFinding({ severity: 'MEDIUM', riskScore: 30 })];
      const result = evaluatePolicy(findings, makeAgency(20), { failOnHigh: true });
      expect(result.shouldFail).toBe(false);
    });

    it('returns fail when HIGH findings exist', () => {
      const findings = [makeFinding({ severity: 'HIGH', subcode: 'WF-002' })];
      const result = evaluatePolicy(findings, makeAgency(50), { failOnHigh: true });
      expect(result.shouldFail).toBe(true);
      expect(result.reason).toContain('HIGH');
      expect(result.reason).toContain('WF-002');
    });
  });

  describe('failOnVerdict', () => {
    it('returns fail when verdict is BLOCK and threshold is BLOCK', () => {
      const result = evaluatePolicy([], makeAgency(85, 'BLOCK'), { failOnVerdict: 'BLOCK' });
      expect(result.shouldFail).toBe(true);
    });

    it('returns fail when verdict is BLOCK and threshold is REVIEW', () => {
      const result = evaluatePolicy([], makeAgency(85, 'BLOCK'), { failOnVerdict: 'REVIEW' });
      expect(result.shouldFail).toBe(true);
    });

    it('returns fail when verdict is REVIEW and threshold is REVIEW', () => {
      const result = evaluatePolicy([], makeAgency(50, 'REVIEW'), { failOnVerdict: 'REVIEW' });
      expect(result.shouldFail).toBe(true);
    });

    it('returns no fail when verdict is below threshold', () => {
      const result = evaluatePolicy([], makeAgency(20, 'PASS'), { failOnVerdict: 'REVIEW' });
      expect(result.shouldFail).toBe(false);
    });
  });

  describe('combined policies', () => {
    it('aggregates multiple failure reasons', () => {
      const findings = [
        makeFinding({ severity: 'CRITICAL', subcode: 'SEC-001', riskScore: 100 }),
      ];
      const result = evaluatePolicy(findings, makeAgency(85, 'BLOCK'), {
        failOnScore: 50,
        failOnCritical: true,
        failOnVerdict: 'BLOCK',
      });
      expect(result.shouldFail).toBe(true);
      expect(result.reason).toContain('CRITICAL');
      expect(result.reason).toContain('threshold');
      expect(result.reason).toContain('BLOCK');
    });
  });
});
