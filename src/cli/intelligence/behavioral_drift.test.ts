import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockReaddirSync, mockStatSync, mockReadFileSync } = vi.hoisted(() => ({
  mockReaddirSync: vi.fn(),
  mockStatSync: vi.fn(),
  mockReadFileSync: vi.fn(),
}));

vi.mock('fs', () => ({
  readdirSync: mockReaddirSync,
  statSync: mockStatSync,
  readFileSync: mockReadFileSync,
  existsSync: vi.fn(),
  mkdirSync: vi.fn(),
  writeFileSync: vi.fn(),
}));

vi.mock('../../core/lite/lite_scanner', () => ({
  LiteScanner: vi.fn().mockImplementation(function() {
    return {
      scanPatch: vi.fn().mockReturnValue([
        { type: 'UNSAFE_EVAL', severity: 'HIGH', file: 'index.js', line: 1, snippet: 'eval("...")', intent: 'NONE' },
      ]),
    };
  }),
  LiteFinding: {} as any,
}));

import { analyzeCapabilities, computeDrift, CapabilitySnapshot } from './behavioral_drift';

describe('BehavioralDrift', () => {
  describe('analyzeCapabilities', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    it('analyzes a package directory and extracts capability snapshot', () => {
      const mockDir = '/fake/package';

      mockReaddirSync.mockImplementation((dir: string) => {
        if (dir === mockDir) return ['index.js'];
        return [];
      });
      mockStatSync.mockReturnValue({ isDirectory: () => false } as any);
      mockReadFileSync.mockReturnValue('eval("risky code")');

      const result = analyzeCapabilities('test-pkg', '1.0.0', mockDir);

      expect(result.packageName).toBe('test-pkg');
      expect(result.version).toBe('1.0.0');
      expect(result.timestamp).toBeTruthy();
      expect(result.capabilities.size).toBeGreaterThan(0);
      expect(result.riskScore).toBeGreaterThan(0);
    });
  });

  describe('computeDrift', () => {
    it('detects new dangerous capability —> MALICIOUS', () => {
      const prev: CapabilitySnapshot = {
        packageName: 'test-pkg',
        version: '1.0.0',
        timestamp: '2024-01-01T00:00:00.000Z',
        capabilities: new Map([['network', 1]]),
        riskScore: 10,
      };
      const curr: CapabilitySnapshot = {
        packageName: 'test-pkg',
        version: '2.0.0',
        timestamp: '2024-06-01T00:00:00.000Z',
        capabilities: new Map([['network', 1], ['eval', 2]]),
        riskScore: 20,
      };

      const result = computeDrift(prev, curr);

      expect(result.verdict).toBe('MALICIOUS');
      expect(result.newCapabilities).toContain('eval');
      expect(result.drifts.length).toBe(1);
      expect(result.drifts[0].severity).toBe('NEW');
    });

    it('detects removed capability —> SAFE', () => {
      const prev: CapabilitySnapshot = {
        packageName: 'test-pkg',
        version: '1.0.0',
        timestamp: '2024-01-01T00:00:00.000Z',
        capabilities: new Map([['network', 1], ['process_spawn', 1]]),
        riskScore: 20,
      };
      const curr: CapabilitySnapshot = {
        packageName: 'test-pkg',
        version: '2.0.0',
        timestamp: '2024-06-01T00:00:00.000Z',
        capabilities: new Map([['network', 1]]),
        riskScore: 10,
      };

      const result = computeDrift(prev, curr);

      expect(result.verdict).toBe('SAFE');
      expect(result.removedCapabilities).toContain('process_spawn');
      expect(result.drifts.length).toBe(1);
      expect(result.drifts[0].severity).toBe('REMOVED');
    });

    it('detects no capability change —> SAFE', () => {
      const prev: CapabilitySnapshot = {
        packageName: 'test-pkg',
        version: '1.0.0',
        timestamp: '2024-01-01T00:00:00.000Z',
        capabilities: new Map([['network', 1]]),
        riskScore: 10,
      };
      const curr: CapabilitySnapshot = {
        packageName: 'test-pkg',
        version: '2.0.0',
        timestamp: '2024-06-01T00:00:00.000Z',
        capabilities: new Map([['network', 1]]),
        riskScore: 10,
      };

      const result = computeDrift(prev, curr);

      expect(result.verdict).toBe('SAFE');
      expect(result.drifts.length).toBe(0);
      expect(result.newCapabilities.length).toBe(0);
      expect(result.removedCapabilities.length).toBe(0);
    });
  });
});
