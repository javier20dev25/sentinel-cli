'use strict';

import * as fs from 'fs';
import * as path from 'path';
import {
  RecordedSession, ReplayResult, ReplayCampaign,
  generateId
} from './types';
import { ReplayEngine } from './replay-engine';

export interface CompareResult {
  sessionId: string;
  sessionName: string;
  baseline: ReplayResult;
  current: ReplayResult;
  differences: {
    riskScoreDiff: number;
    riskLevelChanged: boolean;
    confidenceDiff: number;
    behaviorsAdded: string[];
    behaviorsRemoved: string[];
    errorsChanged: boolean;
  };
}

export function runReplayCampaign(sessionsDir: string): ReplayCampaign {
  const engine = new ReplayEngine();
  const files = fs.readdirSync(sessionsDir)
    .filter(f => f.endsWith('.json') && f !== 'manifest.json')
    .sort();
  if (files.length === 0) {
    throw new Error(`No session JSON files found in ${sessionsDir}`);
  }

  const results: ReplayResult[] = [];
  for (const file of files) {
    const filePath = path.join(sessionsDir, file);
    try {
      const result = engine.replayFile(filePath);
      results.push(result);
      console.log(`  [${result.riskLevel.padEnd(8)}] ${file} — risk ${result.riskScore}, ${result.behaviorsDetected.length} behaviors, ${result.errors.length} errors`);
    } catch (err: any) {
      console.log(`  [ERROR    ] ${file} — ${err.message}`);
    }
  }

  const campaign: ReplayCampaign = {
    id: `rc-${generateId()}`,
    name: path.basename(sessionsDir),
    sessions: [],
    results,
    createdAt: new Date().toISOString(),
    totalPassed: results.filter(r => r.riskLevel === 'LOW').length,
    totalFailed: results.filter(r => r.riskLevel !== 'LOW').length,
  };

  return campaign;
}

export function compareReplayResults(baseline: ReplayResult[], current: ReplayResult[]): CompareResult[] {
  const comparisons: CompareResult[] = [];

  for (const cur of current) {
    const base = baseline.find(b => b.sessionId === cur.sessionId);
    if (!base) continue;

    const baseBehaviors = new Set(base.behaviorsDetected);
    const curBehaviors = new Set(cur.behaviorsDetected);

    const diff: CompareResult = {
      sessionId: cur.sessionId,
      sessionName: cur.sessionName,
      baseline: base,
      current: cur,
      differences: {
        riskScoreDiff: cur.riskScore - base.riskScore,
        riskLevelChanged: cur.riskLevel !== base.riskLevel,
        confidenceDiff: cur.confidence - base.confidence,
        behaviorsAdded: [...curBehaviors].filter(b => !baseBehaviors.has(b)),
        behaviorsRemoved: [...baseBehaviors].filter(b => !curBehaviors.has(b)),
        errorsChanged: JSON.stringify(cur.errors) !== JSON.stringify(base.errors),
      },
    };
    comparisons.push(diff);
  }

  return comparisons;
}

export function renderReplayCampaignSummary(campaign: ReplayCampaign): string {
  const lines: string[] = [];
  lines.push(`Replay Campaign: ${campaign.name}`);
  lines.push(`  ID: ${campaign.id}`);
  lines.push(`  Created: ${campaign.createdAt}`);
  lines.push(`  Sessions: ${campaign.results.length}`);
  lines.push(`  Pass (LOW risk): ${campaign.totalPassed}`);
  lines.push(`  Flagged: ${campaign.totalFailed}`);
  lines.push('');

  const byLevel: Record<string, number> = {};
  for (const r of campaign.results) {
    byLevel[r.riskLevel] = (byLevel[r.riskLevel] || 0) + 1;
  }
  lines.push('  Risk distribution:');
  for (const [level, count] of Object.entries(byLevel).sort()) {
    lines.push(`    ${level.padEnd(10)} ${count}`);
  }
  lines.push('');

  return lines.join('\n');
}

export function renderComparisonSummary(comparisons: CompareResult[]): string {
  const lines: string[] = [];
  lines.push('Replay Comparison (Baseline vs Current)');
  lines.push('');

  let changed = 0;
  for (const c of comparisons) {
    const d = c.differences;
    const hasChanges = d.riskLevelChanged || d.behaviorsAdded.length > 0 || d.behaviorsRemoved.length > 0 || d.errorsChanged;
    if (hasChanges) {
      changed++;
      lines.push(`  ${c.sessionName}:`);
      if (d.riskLevelChanged) lines.push(`    Risk level: ${c.baseline.riskLevel} → ${c.current.riskLevel}`);
      if (d.riskScoreDiff !== 0) lines.push(`    Risk score: ${c.baseline.riskScore} → ${c.current.riskScore} (${d.riskScoreDiff > 0 ? '+' : ''}${d.riskScoreDiff})`);
      if (d.behaviorsAdded.length > 0) lines.push(`    Behaviors added: ${d.behaviorsAdded.join(', ')}`);
      if (d.behaviorsRemoved.length > 0) lines.push(`    Behaviors removed: ${d.behaviorsRemoved.join(', ')}`);
    }
  }

  lines.push('');
  lines.push(`  ${comparisons.length} sessions compared, ${changed} with differences`);
  if (changed === 0) lines.push('  No regressions detected.');
  lines.push('');

  return lines.join('\n');
}
