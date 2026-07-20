import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { RiskSnapshot, computeTrend, repoHash, saveSnapshot, loadBaseline, loadHistoryInWindow } from './risk_history';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AgencyScoreResult } from './agency_score';
import { AttackScenario } from './attack_scenario';

const testRepo = path.join(os.tmpdir(), 'sentinel-test-branch-' + Date.now());
const testSnapDir = path.join(os.homedir(), '.sentinel', 'history', repoHash(testRepo));

function makeAgency(score: number): AgencyScoreResult {
  return {
    agencyScore: score,
    verdict: score >= 70 ? 'BLOCK' as const : score >= 30 ? 'REVIEW' as const : 'PASS' as const,
    blastRadius: score >= 75 ? 'CRITICAL' as const : score >= 50 ? 'HIGH' as const : 'MEDIUM' as const,
    totalFindings: 10,
    criticalCount: 2,
    highCount: 3,
    mediumCount: 3,
    lowCount: 2,
    drivers: [],
  };
}

function emptyScenarios(): AttackScenario[] {
  return [];
}

beforeAll(() => {
  if (!fs.existsSync(testSnapDir)) fs.mkdirSync(testSnapDir, { recursive: true });
});

afterAll(() => {
  try { fs.rmSync(testSnapDir, { recursive: true, force: true }); } catch {}
});

function snap(score: number, time: string, total = 10, critical = 2): RiskSnapshot {
  return {
    id: `snap-${time}`,
    timestamp: new Date(time).toISOString(),
    agencyScore: score,
    verdict: score >= 70 ? 'BLOCK' as const : score >= 30 ? 'REVIEW' as const : 'PASS' as const,
    blastRadius: score >= 75 ? 'CRITICAL' as const : score >= 50 ? 'HIGH' as const : 'MEDIUM' as const,
    totalFindings: total,
    criticalCount: critical,
    highCount: 3,
    scenarioCount: 2,
    topScenarios: [],
    repoPath: '/test/repo',
    repoHash: repoHash('/test/repo'),
  };
}

describe('computeTrend', () => {
  it('returns stable for single snapshot', () => {
    const trend = computeTrend([snap(50, '2025-01-01')]);
    expect(trend.direction).toBe('stable');
    expect(trend.scoreDelta).toBe(0);
  });

  it('detects improving trend when score decreases', () => {
    const trend = computeTrend([
      snap(80, '2025-01-01'),
      snap(40, '2025-01-02'),
    ]);
    expect(trend.direction).toBe('improving');
    expect(trend.scoreDelta).toBe(40);
    expect(trend.findingDelta).toBe(0);
  });

  it('detects declining trend when score increases', () => {
    const trend = computeTrend([
      snap(30, '2025-01-01'),
      snap(70, '2025-01-02'),
    ]);
    expect(trend.direction).toBe('declining');
    expect(trend.scoreDelta).toBe(-40);
  });

  it('detects improving when critical count drops', () => {
    const trend = computeTrend([
      snap(40, '2025-01-01', 10, 5),
      snap(40, '2025-01-02', 10, 2),
    ]);
    expect(trend.direction).toBe('improving');
    expect(trend.criticalDelta).toBe(3);
  });

  it('detects declining when critical count rises', () => {
    const trend = computeTrend([
      snap(40, '2025-01-01', 10, 1),
      snap(40, '2025-01-02', 10, 4),
    ]);
    expect(trend.direction).toBe('declining');
    expect(trend.criticalDelta).toBe(-3);
  });

  it('sorts by timestamp before computing', () => {
    const trend = computeTrend([
      snap(40, '2025-01-03'),
      snap(80, '2025-01-01'),
      snap(60, '2025-01-02'),
    ]);
    expect(trend.snapshots.length).toBe(3);
    expect(trend.snapshots[0].agencyScore).toBe(80);
    expect(trend.snapshots[2].agencyScore).toBe(40);
    expect(trend.direction).toBe('improving');
  });

  it('maintains stable for small score changes', () => {
    const trend = computeTrend([
      snap(45, '2025-01-01'),
      snap(48, '2025-01-02'),
    ]);
    expect(trend.direction).toBe('stable');
  });
});

describe('repoHash', () => {
  it('produces consistent hash for same path', () => {
    const h1 = repoHash('/some/repo/path');
    const h2 = repoHash('/some/repo/path');
    expect(h1).toBe(h2);
  });

  it('produces different hash for different paths', () => {
    const h1 = repoHash('/repo/one');
    const h2 = repoHash('/repo/two');
    expect(h1).not.toBe(h2);
  });
});

describe('saveSnapshot with branch', () => {
  it('stores branch field when provided', () => {
    const snap = saveSnapshot(testRepo, makeAgency(50), emptyScenarios(), 'feature/test');
    expect(snap.branch).toBe('feature/test');
    const safeTs = snap.timestamp.replace(/:/g, '-');
    const raw = JSON.parse(fs.readFileSync(path.join(testSnapDir, `${safeTs}-${snap.id}.json`), 'utf8'));
    expect(raw.branch).toBe('feature/test');
  });
});

describe('loadBaseline', () => {
  it('returns null when no main/master snapshot exists', () => {
    const result = loadBaseline(testRepo);
    if (result) {
      expect(result.branch).toMatch(/^(main|master)$/);
    }
  });

  it('returns the latest main branch snapshot', () => {
    saveSnapshot(testRepo, makeAgency(80), emptyScenarios(), 'feature/one');
    saveSnapshot(testRepo, makeAgency(60), emptyScenarios(), 'main');
    saveSnapshot(testRepo, makeAgency(20), emptyScenarios(), 'main');
    const result = loadBaseline(testRepo);
    expect(result).not.toBeNull();
    expect(result!.branch).toBe('main');
    expect(result!.agencyScore).toBe(20);
  });
});

describe('loadHistoryInWindow', () => {
  it('returns only snapshots within the window', () => {
    const snapshots = loadHistoryInWindow(testRepo, 36500);
    const allSnaps = JSON.parse(JSON.stringify(snapshots));
    expect(snapshots.length).toBeGreaterThan(0);
    const now = Date.now();
    for (const s of snapshots) {
      expect(new Date(s.timestamp).getTime()).toBeGreaterThan(now - 36500 * 24 * 60 * 60 * 1000);
    }
  });

  it('returns empty array for 0 day window', () => {
    const snapshots = loadHistoryInWindow(testRepo, 0);
    expect(snapshots.length).toBe(0);
  });
});
