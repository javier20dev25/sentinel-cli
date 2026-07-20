import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { execSync } from 'child_process';

let _snapshotSeq = 0;
import { AgencyScoreResult } from './agency_score';
import { AttackScenario } from './attack_scenario';

export interface RiskSnapshot {
  id: string;
  timestamp: string;
  agencyScore: number;
  verdict: string;
  blastRadius: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  scenarioCount: number;
  topScenarios: { id: string; name: string; score: number; severity: string }[];
  repoPath: string;
  repoHash: string;
  branch?: string;
}

export interface RiskTrend {
  snapshots: RiskSnapshot[];
  direction: 'improving' | 'declining' | 'stable';
  scoreDelta: number;
  findingDelta: number;
  criticalDelta: number;
}

function getHistoryDir(): string {
  return path.join(os.homedir(), '.sentinel', 'history');
}

export function repoHash(repoPath: string): string {
  return crypto.createHash('sha256').update(path.resolve(repoPath)).digest('hex').substring(0, 12);
}

function detectBranch(repoPath: string): string | undefined {
  try {
    return execSync('git rev-parse --abbrev-ref HEAD', {
      cwd: repoPath,
      encoding: 'utf8',
      timeout: 5000,
    }).trim();
  } catch {
    return undefined;
  }
}

export function saveSnapshot(
  repoPath: string,
  agency: AgencyScoreResult,
  scenarios: AttackScenario[],
  branch?: string,
): RiskSnapshot {
  const dir = path.join(getHistoryDir(), repoHash(repoPath));
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const id = Date.now().toString(36) + '-' + (_snapshotSeq++).toString(36).padStart(4, '0');
  const effectiveBranch = branch ?? detectBranch(repoPath);
  const snapshot: RiskSnapshot = {
    id,
    timestamp: new Date().toISOString(),
    agencyScore: agency.agencyScore,
    verdict: agency.verdict,
    blastRadius: agency.blastRadius,
    totalFindings: agency.totalFindings,
    criticalCount: agency.criticalCount,
    highCount: agency.highCount,
    scenarioCount: scenarios.length,
    topScenarios: scenarios.slice(0, 5).map(s => ({
      id: s.id,
      name: s.name,
      score: s.score,
      severity: s.severity,
    })),
    repoPath: path.resolve(repoPath),
    repoHash: repoHash(repoPath),
    branch: effectiveBranch,
  };

  const safeTs = snapshot.timestamp.replace(/:/g, '-');
  fs.writeFileSync(path.join(dir, `${safeTs}-${id}.json`), JSON.stringify(snapshot, null, 2));
  return snapshot;
}

export function loadHistory(repoPath: string): RiskSnapshot[] {
  const dir = path.join(getHistoryDir(), repoHash(repoPath));
  if (!fs.existsSync(dir)) return [];

  const entries = fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse();

  const snapshots: RiskSnapshot[] = [];
  for (const entry of entries) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(dir, entry), 'utf8'));
      snapshots.push(data as RiskSnapshot);
    } catch {}
  }
  return snapshots;
}

export function loadBaseline(repoPath: string): RiskSnapshot | null {
  const history = loadHistory(repoPath).sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  return history.find(s => s.branch === 'main' || s.branch === 'master') || null;
}

export function loadHistoryInWindow(repoPath: string, days: number): RiskSnapshot[] {
  const history = loadHistory(repoPath);
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  return history.filter(s => new Date(s.timestamp).getTime() >= cutoff);
}

export function computeTrendInWindow(repoPath: string, days: number): RiskTrend {
  return computeTrend(loadHistoryInWindow(repoPath, days));
}

export function loadAllHistory(): Map<string, RiskSnapshot[]> {
  const base = getHistoryDir();
  if (!fs.existsSync(base)) return new Map();

  const repos = new Map<string, RiskSnapshot[]>();
  const dirs = fs.readdirSync(base);
  for (const dir of dirs) {
    const dirPath = path.join(base, dir);
    if (!fs.statSync(dirPath).isDirectory()) continue;
    try {
      const snapshots = fs.readdirSync(dirPath)
        .filter(f => f.endsWith('.json'))
        .sort()
        .reverse()
        .map(f => JSON.parse(fs.readFileSync(path.join(dirPath, f), 'utf8')) as RiskSnapshot);
      if (snapshots.length > 0) {
        repos.set(snapshots[0].repoPath, snapshots);
      }
    } catch {}
  }
  return repos;
}

export function computeTrend(snapshots: RiskSnapshot[]): RiskTrend {
  if (snapshots.length < 2) {
    return {
      snapshots,
      direction: 'stable',
      scoreDelta: 0,
      findingDelta: 0,
      criticalDelta: 0,
    };
  }

  const sorted = [...snapshots].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const current = sorted[sorted.length - 1];
  const previous = sorted[sorted.length - 2];

  const scoreDelta = previous.agencyScore - current.agencyScore;
  const findingDelta = previous.totalFindings - current.totalFindings;
  const criticalDelta = previous.criticalCount - current.criticalCount;

  let direction: RiskTrend['direction'] = 'stable';
  if (scoreDelta > 5 || criticalDelta > 0) direction = 'improving';
  else if (scoreDelta < -5 || criticalDelta < 0) direction = 'declining';

  return {
    snapshots: sorted,
    direction,
    scoreDelta,
    findingDelta,
    criticalDelta,
  };
}
