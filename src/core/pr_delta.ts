import { LiteFinding } from './lite/lite_scanner';
import { RiskSnapshot, loadHistory, loadBaseline } from './risk_history';
import { AgencyScoreResult } from './agency_score';

export interface FindingDelta {
  newFindings: LiteFinding[];
  fixedFindings: { subcode: string; file: string; line: number; title: string }[];
  scoreDelta: number;
  criticalDelta: number;
  highDelta: number;
  totalBefore: number;
  totalAfter: number;
}

function findingKey(f: LiteFinding): string {
  return `${f.subcode || f.type}|${f.file}|${f.line}`;
}

export function computeDelta(
  currentFindings: LiteFinding[],
  snapshot: RiskSnapshot,
  previousFindings?: LiteFinding[],
): FindingDelta {
  const prevFindings = previousFindings || [];
  const currentKeys = new Set(currentFindings.map(f => findingKey(f)));
  const prevKeys = new Set(prevFindings.map(f => findingKey(f)));

  const fixedFindings = prevFindings
    .filter(f => !currentKeys.has(findingKey(f)))
    .map(f => ({
      subcode: f.subcode || f.type,
      file: f.file,
      line: f.line,
      title: f.title || f.type,
    }));

  const newFindings = currentFindings
    .filter(f => !prevKeys.has(findingKey(f)));

  const criticalBefore = snapshot.criticalCount;
  const highBefore = snapshot.highCount;
  const criticalNow = currentFindings.filter(f => f.severity === 'CRITICAL').length;
  const highNow = currentFindings.filter(f => f.severity === 'HIGH').length;

  return {
    newFindings,
    fixedFindings,
    scoreDelta: 0,
    criticalDelta: criticalNow - criticalBefore,
    highDelta: highNow - highBefore,
    totalBefore: prevFindings.length,
    totalAfter: currentFindings.length,
  };
}

export function computeDeltaVsLatest(
  currentFindings: LiteFinding[],
  repoPath: string,
): { delta: FindingDelta | null; baseline: RiskSnapshot | null } {
  const history = loadHistory(repoPath);
  const latest = history[0];
  if (!latest) return { delta: null, baseline: null };

  const delta: FindingDelta = {
    newFindings: [],
    fixedFindings: [],
    scoreDelta: 0,
    criticalDelta: 0,
    highDelta: 0,
    totalBefore: latest.totalFindings,
    totalAfter: currentFindings.length,
  };

  const criticalBefore = latest.criticalCount;
  const criticalNow = currentFindings.filter(f => f.severity === 'CRITICAL').length;
  const highBefore = latest.highCount;
  const highNow = currentFindings.filter(f => f.severity === 'HIGH').length;

  delta.criticalDelta = criticalNow - criticalBefore;
  delta.highDelta = highNow - highBefore;

  return { delta, baseline: latest };
}

export function computeDeltaVsBaseline(
  currentFindings: LiteFinding[],
  currentAgency: AgencyScoreResult,
  repoPath: string,
  baselineBranch?: string,
): { delta: FindingDelta | null; baseline: RiskSnapshot | null } {
  let baseline: RiskSnapshot | null = null;

  if (baselineBranch) {
    const history = loadHistory(repoPath);
    baseline = history.find(s => s.branch === baselineBranch) || null;
  } else {
    baseline = loadBaseline(repoPath);
    if (!baseline) {
      const history = loadHistory(repoPath);
      baseline = history[0] || null;
    }
  }

  if (!baseline) return { delta: null, baseline: null };

  const criticalNow = currentFindings.filter(f => f.severity === 'CRITICAL').length;
  const highNow = currentFindings.filter(f => f.severity === 'HIGH').length;

  const delta: FindingDelta = {
    newFindings: [],
    fixedFindings: [],
    scoreDelta: baseline.agencyScore - currentAgency.agencyScore,
    criticalDelta: criticalNow - baseline.criticalCount,
    highDelta: highNow - baseline.highCount,
    totalBefore: baseline.totalFindings,
    totalAfter: currentFindings.length,
  };

  return { delta, baseline };
}
