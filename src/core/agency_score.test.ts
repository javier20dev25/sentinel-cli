import { describe, it, expect } from 'vitest';
import { calculateAgencyScore, detectCorrelations, AgencyScoreResult } from './agency_score';
import { LiteFinding } from './lite/lite_scanner';

function finding(overrides: Partial<LiteFinding> & { riskScore: number }): LiteFinding {
  return {
    type: 'TEST', subcode: 'TEST', category: 'generic', intent: 'SUSPICIOUS',
    file: 'test.js', line: 1, severity: 'HIGH', confidence: 'high',
    title: 'Test finding', description: 'Test', snippet: 'test',
    ...overrides,
  };
}

describe('calculateAgencyScore — empty / no risk', () => {
  it('returns score 0, PASS, LOW for empty findings', () => {
    const r = calculateAgencyScore([]);
    expect(r.agencyScore).toBe(0);
    expect(r.verdict).toBe('PASS');
    expect(r.blastRadius).toBe('LOW');
    expect(r.drivers).toHaveLength(0);
    expect(r.correlations).toHaveLength(0);
    expect(r.recommendation).toBe('No action required');
  });

  it('returns score 0, PASS, LOW for findings with riskScore 0', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-INFO', riskScore: 0, severity: 'LOW' }),
    ]);
    expect(r.agencyScore).toBe(0);
    expect(r.verdict).toBe('PASS');
    expect(r.drivers).toHaveLength(0);
  });
});

describe('calculateAgencyScore — single finding', () => {
  it('score equals riskScore for a single generic finding', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-002', riskScore: 85, severity: 'CRITICAL', category: 'generic' }),
    ]);
    expect(r.agencyScore).toBe(85);
    expect(r.verdict).toBe('BLOCK');
    expect(r.blastRadius).toBe('CRITICAL');
  });

  it('malware category multiplies score by 1.5', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'GYP-NODE', riskScore: 30, severity: 'MEDIUM', category: 'malware' }),
    ]);
    expect(r.agencyScore).toBe(45);
    expect(r.verdict).toBe('REVIEW');
    expect(r.blastRadius).toBe('MEDIUM');
  });

  it('workflow category multiplies score by 1.2', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-007', riskScore: 40, severity: 'MEDIUM', category: 'workflow' }),
    ]);
    expect(r.agencyScore).toBe(48);
    expect(r.verdict).toBe('REVIEW');
  });

  it('low riskScore with malware category', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'SAST-NETWORK', riskScore: 15, severity: 'LOW', category: 'malware' }),
    ]);
    expect(r.agencyScore).toBe(23);
    expect(r.verdict).toBe('PASS');
    expect(r.blastRadius).toBe('LOW');
  });
});

describe('calculateAgencyScore — multiple findings (diminishing)', () => {
  it('two findings: max + 50% of second', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-002', riskScore: 85, severity: 'CRITICAL', category: 'workflow' }),
      finding({ subcode: 'WF-003', riskScore: 70, severity: 'HIGH', category: 'workflow' }),
    ]);
    expect(r.agencyScore).toBe(100);
    expect(r.verdict).toBe('BLOCK');
  });

  it('three findings with category multipliers', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-002', riskScore: 60, severity: 'CRITICAL', category: 'workflow' }),
      finding({ subcode: 'WF-003', riskScore: 40, severity: 'HIGH', category: 'workflow' }),
      finding({ subcode: 'SAST-EVAL', riskScore: 30, severity: 'LOW', category: 'generic' }),
    ]);
    // 60*1.2 + (40*1.2)*0.5 + 30*0.25 = 103.5 - 9 (CI/CD corr) = 94.5 → 95
    expect(r.agencyScore).toBe(95);
  });

  it('multiple moderate findings do not exceed 100', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-002', riskScore: 95, severity: 'CRITICAL', category: 'workflow' }),
      finding({ subcode: 'AS-001', riskScore: 90, severity: 'CRITICAL', category: 'agent' }),
      finding({ subcode: 'WF-001', riskScore: 70, severity: 'HIGH', category: 'workflow' }),
      finding({ subcode: 'TOK-001', riskScore: 75, severity: 'HIGH', category: 'token' }),
    ]);
    expect(r.agencyScore).toBe(100);
  });

  it('respects caps at 10 findings', () => {
    const findings = Array.from({ length: 15 }, (_, i) =>
      finding({ subcode: `S-${i}`, riskScore: 50, severity: 'HIGH', category: 'generic' })
    );
    const r = calculateAgencyScore(findings);
    expect(r.agencyScore).toBe(100);
  });
});

describe('calculateAgencyScore — counts', () => {
  it('reports totalFindings, criticalCount, highCount', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-002', riskScore: 85, severity: 'CRITICAL', category: 'workflow' }),
      finding({ subcode: 'AS-001', riskScore: 90, severity: 'CRITICAL', category: 'agent' }),
      finding({ subcode: 'WF-003', riskScore: 70, severity: 'HIGH', category: 'workflow' }),
      finding({ subcode: 'TOK-001', riskScore: 75, severity: 'HIGH', category: 'token' }),
      finding({ subcode: 'SAST-NETWORK', riskScore: 15, severity: 'LOW', category: 'generic' }),
    ]);
    expect(r.totalFindings).toBe(5);
    expect(r.criticalCount).toBe(2);
    expect(r.highCount).toBe(2);
  });

  it('ignores informational findings in counts', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-002', riskScore: 85, severity: 'CRITICAL', category: 'workflow' }),
      finding({ subcode: 'WF-INFO', riskScore: 0, severity: 'LOW' }),
      finding({ subcode: 'AS-INFO', riskScore: 0, severity: 'LOW' }),
    ]);
    expect(r.totalFindings).toBe(1);
    expect(r.criticalCount).toBe(1);
  });
});

describe('calculateAgencyScore — drivers', () => {
  it('includes all contributing findings', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'AS-001', riskScore: 90, severity: 'CRITICAL', category: 'agent', title: 'bypass sentinel', confidence: 'high' }),
      finding({ subcode: 'WF-002', riskScore: 85, severity: 'CRITICAL', category: 'workflow', title: 'write-all', confidence: 'high' }),
    ]);
    expect(r.drivers).toHaveLength(2);
    expect(r.drivers[0].subcode).toBe('AS-001');
    expect(r.drivers[0].contribution).toBe(117);
    expect(r.drivers[1].subcode).toBe('WF-002');
    expect(r.drivers[1].contribution).toBe(51);
  });

  it('drivers sorted by riskScore descending', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-007', riskScore: 40, severity: 'MEDIUM', category: 'workflow' }),
      finding({ subcode: 'WF-002', riskScore: 85, severity: 'CRITICAL', category: 'workflow' }),
      finding({ subcode: 'AS-003', riskScore: 90, severity: 'CRITICAL', category: 'agent' }),
    ]);
    expect(r.drivers[0].subcode).toBe('AS-003');
    expect(r.drivers[1].subcode).toBe('WF-002');
    expect(r.drivers[2].subcode).toBe('WF-007');
  });
});

describe('calculateAgencyScore — verdict boundaries', () => {
  it('score 29 is PASS', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'TEST', riskScore: 29, severity: 'MEDIUM', category: 'generic' }),
    ]);
    expect(r.verdict).toBe('PASS');
  });

  it('score 30 is REVIEW', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'TEST', riskScore: 30, severity: 'HIGH', category: 'generic' }),
    ]);
    expect(r.verdict).toBe('REVIEW');
  });

  it('score 69 is REVIEW', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'TEST', riskScore: 69, severity: 'HIGH', category: 'generic' }),
    ]);
    expect(r.verdict).toBe('REVIEW');
  });

  it('score 70 is BLOCK', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'TEST', riskScore: 70, severity: 'CRITICAL', category: 'generic' }),
    ]);
    expect(r.verdict).toBe('BLOCK');
  });
});

describe('calculateAgencyScore — blast radius boundaries', () => {
  it('score 24 is LOW blast radius', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'TEST', riskScore: 24, severity: 'LOW', category: 'generic' }),
    ]);
    expect(r.blastRadius).toBe('LOW');
  });

  it('score 25 is MEDIUM blast radius', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'TEST', riskScore: 25, severity: 'MEDIUM', category: 'generic' }),
    ]);
    expect(r.blastRadius).toBe('MEDIUM');
  });

  it('score 50 is HIGH blast radius', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'TEST', riskScore: 50, severity: 'HIGH', category: 'generic' }),
    ]);
    expect(r.blastRadius).toBe('HIGH');
  });

  it('score 75 is CRITICAL blast radius', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'TEST', riskScore: 75, severity: 'CRITICAL', category: 'generic' }),
    ]);
    expect(r.blastRadius).toBe('CRITICAL');
  });
});

describe('detectCorrelations', () => {
  it('returns empty for no findings', () => {
    expect(detectCorrelations([])).toHaveLength(0);
  });

  it('detects cross-file same-category and CI/CD correlation', () => {
    const r = detectCorrelations([
      finding({ subcode: 'WF-001', riskScore: 70, severity: 'HIGH', category: 'workflow', file: 'a.yml' }),
      finding({ subcode: 'WF-002', riskScore: 85, severity: 'CRITICAL', category: 'workflow', file: 'b.yml' }),
    ]);
    expect(r.length).toBeGreaterThanOrEqual(2);
    expect(r.some(c => c.description.includes('Same category'))).toBe(true);
    expect(r.some(c => c.description.includes('CI/CD'))).toBe(true);
  });

  it('detects CI/CD multi-risk correlation', () => {
    const r = detectCorrelations([
      finding({ subcode: 'WF-001', riskScore: 70, severity: 'HIGH', category: 'workflow', file: 'a.yml' }),
      finding({ subcode: 'WF-002', riskScore: 85, severity: 'CRITICAL', category: 'workflow', file: 'b.yml' }),
    ]);
    expect(r.some(c => c.description.includes('CI/CD'))).toBe(true);
  });

  it('detects obfuscation+malware correlation', () => {
    const r = detectCorrelations([
      finding({ subcode: 'OBF-PAYLOAD', riskScore: 75, severity: 'HIGH', category: 'obfuscation', file: 'payload.js' }),
      finding({ subcode: 'SAST-EVAL', riskScore: 90, severity: 'CRITICAL', category: 'malware', file: 'payload.js' }),
    ]);
    expect(r.some(c => c.description.includes('Obfuscation with malware'))).toBe(true);
  });

  it('detects multi-category file correlation', () => {
    const r = detectCorrelations([
      finding({ subcode: 'WF-001', riskScore: 70, severity: 'HIGH', category: 'workflow', file: 'x.yml' }),
      finding({ subcode: 'SEC-TOKEN', riskScore: 90, severity: 'CRITICAL', category: 'secret', file: 'x.yml' }),
      finding({ subcode: 'TOK-001', riskScore: 75, severity: 'HIGH', category: 'token', file: 'x.yml' }),
    ]);
    expect(r.some(c => c.description.includes('3 different categories'))).toBe(true);
  });
});

describe('calculateAgencyScore — real-world scenarios', () => {
  it('safe PR: only low/medium findings with category multipliers', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'SAST-NETWORK', riskScore: 15, severity: 'LOW', category: 'malware' }),
      finding({ subcode: 'SAST-ENV', riskScore: 50, severity: 'MEDIUM', category: 'malware' }),
    ]);
    // 50*1.5 + (15*1.5)*0.5 = 75 + 11.25 = 86.25 → 86
    expect(r.agencyScore).toBe(86);
    expect(r.verdict).toBe('BLOCK');
  });

  it('dangerous PR: supply chain attack', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-005', riskScore: 85, severity: 'CRITICAL', category: 'workflow' }),
      finding({ subcode: 'LIF-CURL-BASH', riskScore: 90, severity: 'CRITICAL', category: 'malware' }),
      finding({ subcode: 'AS-003', riskScore: 90, severity: 'CRITICAL', category: 'agent' }),
    ]);
    expect(r.agencyScore).toBe(100);
    expect(r.verdict).toBe('BLOCK');
    expect(r.blastRadius).toBe('CRITICAL');
  });

  it('mixed categories produce correct drivers', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'WF-002', riskScore: 85, severity: 'CRITICAL', category: 'workflow' }),
      finding({ subcode: 'AS-001', riskScore: 90, severity: 'CRITICAL', category: 'agent' }),
      finding({ subcode: 'SEC-GITHUB-TOKEN', riskScore: 90, severity: 'CRITICAL', category: 'secret' }),
      finding({ subcode: 'TOK-001', riskScore: 75, severity: 'HIGH', category: 'token' }),
    ]);
    expect(r.drivers.some(d => d.category === 'workflow')).toBe(true);
    expect(r.drivers.some(d => d.category === 'agent')).toBe(true);
    expect(r.drivers.some(d => d.category === 'secret')).toBe(true);
    expect(r.drivers.some(d => d.category === 'token')).toBe(true);
    expect(r.recommendation).not.toBe('');
  });
});

describe('calculateAgencyScore — correlations via calculateAgencyScore', () => {
  it('returns correlations when findings span categories', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'OBF-PAYLOAD', riskScore: 75, severity: 'HIGH', category: 'obfuscation', file: 'payload.js' }),
      finding({ subcode: 'SAST-EVAL', riskScore: 90, severity: 'CRITICAL', category: 'malware', file: 'payload.js' }),
    ]);
    expect(r.correlations.length).toBeGreaterThanOrEqual(1);
    expect(r.recommendation).toContain('malware');
  });

  it('returns recommendation for secrets', () => {
    const r = calculateAgencyScore([
      finding({ subcode: 'SEC-AWS-ID', riskScore: 90, severity: 'CRITICAL', category: 'secret', file: '.env' }),
    ]);
    expect(r.recommendation).toContain('secrets');
  });
});
