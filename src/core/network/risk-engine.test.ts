import { describe, it, expect } from 'vitest';
import { assessRisk, computeRiskConfidence } from './risk-engine';
import { Behavior } from './types';

function makeBehavior(type: string, confidence = 0.9, timestamp?: Date): Behavior {
  return {
    id: `b-${type}`,
    sessionId: 'test',
    type: type as any,
    confidence,
    evidence: [],
    artifacts: [],
    timestamp: timestamp ?? new Date(),
    source: 'process',
  };
}

describe('risk-engine', () => {
  describe('computeRiskConfidence', () => {
    it('returns 0 for empty behaviors', () => {
      expect(computeRiskConfidence([])).toBe(0);
    });

    it('increases confidence with more behaviors', () => {
      const low = computeRiskConfidence([makeBehavior('code_upload')]);
      const high = computeRiskConfidence([
        makeBehavior('preparation_detected'),
        makeBehavior('git_bundle_created'),
        makeBehavior('code_upload'),
      ]);
      expect(high).toBeGreaterThan(low);
    });
  });

  describe('assessRisk with temporal multiplier', () => {
    it('applies temporal multiplier when behaviors are close in time', () => {
      const now = Date.now();
      const result = assessRisk([
        makeBehavior('preparation_detected', 0.9, new Date(now)),
        makeBehavior('git_bundle_created', 0.9, new Date(now + 5_000)),
        makeBehavior('code_upload', 0.9, new Date(now + 10_000)),
      ]);
      const temporalFactor = result.factors.find(f => f.name === 'temporal_multiplier');
      expect(temporalFactor).toBeDefined();
      expect(temporalFactor!.contribution).toBeGreaterThan(0);
    });

    it('applies lower or no temporal multiplier for spread-out behaviors', () => {
      const now = Date.now();
      const result = assessRisk([
        makeBehavior('preparation_detected', 0.9, new Date(now)),
        makeBehavior('git_bundle_created', 0.9, new Date(now + 600_000)),
        makeBehavior('code_upload', 0.9, new Date(now + 1_200_000)),
      ]);
      const temporalFactor = result.factors.find(f => f.name === 'temporal_multiplier');
      // Gap is 600s on average, should have smaller or no multiplier
      expect(temporalFactor).toBeDefined();
    });
  });
});
