import { describe, it, expect } from 'vitest';
import {
  buildEvidenceChain,
  verifyEvidenceChain,
  EvidenceRecord,
} from './evidence-chain-crypto';
import { Evidence } from './types';

function makeEvidence(overrides: Partial<Evidence> & { id: string; timestamp: Date }): Evidence {
  return {
    sessionId: 'test',
    flowId: undefined,
    behaviorId: undefined,
    type: 'behavior_classification',
    title: 'test event',
    description: '',
    data: {},
    severity: 'info',
    ...overrides,
  };
}

describe('evidence-chain-crypto', () => {
  it('builds a chain with correct hashes', () => {
    const ev1 = makeEvidence({ id: 'ev1', timestamp: new Date('2024-01-01T00:00:00Z') });
    const ev2 = makeEvidence({ id: 'ev2', timestamp: new Date('2024-01-01T00:00:01Z') });
    const chain = buildEvidenceChain([ev1, ev2]);

    expect(chain).toHaveLength(2);
    expect(chain[0].previousHash).toBeNull();
    expect(chain[0].hash).toBeTruthy();
    expect(chain[1].previousHash).toBe(chain[0].hash);
    expect(chain[1].hash).not.toBe(chain[0].hash);
  });

  it('verifies an unmodified chain', () => {
    const ev1 = makeEvidence({ id: 'ev1', timestamp: new Date('2024-01-01T00:00:00Z') });
    const ev2 = makeEvidence({ id: 'ev2', timestamp: new Date('2024-01-01T00:00:01Z') });
    const chain = buildEvidenceChain([ev1, ev2]);
    const verification = verifyEvidenceChain(chain);

    expect(verification.chainValid).toBe(true);
    expect(verification.totalRecords).toBe(2);
    expect(verification.tamperedIndices).toEqual([]);
  });

  it('detects tampered hash in chain', () => {
    const ev1 = makeEvidence({ id: 'ev1', timestamp: new Date('2024-01-01T00:00:00Z') });
    const ev2 = makeEvidence({ id: 'ev2', timestamp: new Date('2024-01-01T00:00:01Z') });
    const chain = buildEvidenceChain([ev1, ev2]);

    // Tamper with the second record's hash
    const tampered: EvidenceRecord[] = [
      { ...chain[0] },
      { ...chain[1], hash: '0000deadbeef0000' },
    ];
    const verification = verifyEvidenceChain(tampered);
    expect(verification.chainValid).toBe(false);
    expect(verification.tamperedIndices).toContain(1);
  });

  it('detects broken previousHash link', () => {
    const ev1 = makeEvidence({ id: 'ev1', timestamp: new Date('2024-01-01T00:00:00Z') });
    const ev2 = makeEvidence({ id: 'ev2', timestamp: new Date('2024-01-01T00:00:01Z') });
    const chain = buildEvidenceChain([ev1, ev2]);

    const tampered: EvidenceRecord[] = [
      { ...chain[0] },
      { ...chain[1], previousHash: '0000deadbeef0000' },
    ];
    const verification = verifyEvidenceChain(tampered);
    expect(verification.chainValid).toBe(false);
    expect(verification.tamperedIndices).toContain(1);
  });

  it('handles single record chain', () => {
    const ev1 = makeEvidence({ id: 'ev1', timestamp: new Date('2024-01-01T00:00:00Z') });
    const chain = buildEvidenceChain([ev1]);
    const verification = verifyEvidenceChain(chain);

    expect(verification.chainValid).toBe(true);
    expect(verification.totalRecords).toBe(1);
  });

  it('sorts evidence by timestamp', () => {
    const ev1 = makeEvidence({ id: 'ev1', timestamp: new Date('2024-01-01T00:00:02Z') });
    const ev2 = makeEvidence({ id: 'ev2', timestamp: new Date('2024-01-01T00:00:01Z') });
    const ev3 = makeEvidence({ id: 'ev3', timestamp: new Date('2024-01-01T00:00:00Z') });
    const chain = buildEvidenceChain([ev1, ev2, ev3]);

    expect(chain[0].evidenceId).toBe('ev3');
    expect(chain[1].evidenceId).toBe('ev2');
    expect(chain[2].evidenceId).toBe('ev1');
  });
});
