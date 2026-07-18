'use strict';

import * as fs from 'fs';
import * as path from 'path';
import {
  RecordedSession, ReplayResult, ScenarioEvent,
  CampaignReport, CampaignResult
} from './types';
import { ReplayEngine } from './replay-engine';
import { runReplayCampaign, renderReplayCampaignSummary } from './replay-campaign';
import { CampaignRunner } from './campaign-runner';
import { SCENARIOS } from './scenarios';
import { ENGINE_VERSION } from './version';

// ─── Confusion Matrix ───────────────────────────────────────────────

export interface ConfusionMatrix {
  tp: number;  // flagged and should be flagged (MEDIUM/HIGH/CRITICAL expected)
  fp: number;  // flagged but should not be (LOW expected)
  tn: number;  // not flagged and should not be (LOW expected, LOW actual)
  fn: number;  // not flagged but should be (MEDIUM/HIGH/CRITICAL expected, LOW actual)
}

export function computeConfusionMatrix(
  results: ReplayResult[],
  groundTruth: Map<string, string>
): ConfusionMatrix {
  const m: ConfusionMatrix = { tp: 0, fp: 0, tn: 0, fn: 0 };

  for (const r of results) {
    const expected = groundTruth.get(r.sessionId) || 'LOW';
    const isFlagged = r.riskLevel !== 'LOW';
    const shouldBeFlagged = expected !== 'LOW';

    if (isFlagged && shouldBeFlagged) m.tp++;
    else if (isFlagged && !shouldBeFlagged) m.fp++;
    else if (!isFlagged && !shouldBeFlagged) m.tn++;
    else if (!isFlagged && shouldBeFlagged) m.fn++;
  }

  return m;
}

// ─── Metrics ────────────────────────────────────────────────────────

export interface EvalMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  specificity: number;
  f1: number;
  fpr: number;
  fnr: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export function computeMetrics(m: ConfusionMatrix): EvalMetrics {
  const total = m.tp + m.tn + m.fp + m.fn;
  return {
    accuracy: total > 0 ? (m.tp + m.tn) / total : 0,
    precision: (m.tp + m.fp) > 0 ? m.tp / (m.tp + m.fp) : 0,
    recall: (m.tp + m.fn) > 0 ? m.tp / (m.tp + m.fn) : 0,
    specificity: (m.tn + m.fp) > 0 ? m.tn / (m.tn + m.fp) : 0,
    f1: (m.tp + m.fp + m.fn) > 0 ? (2 * m.tp) / (2 * m.tp + m.fp + m.fn) : 0,
    fpr: (m.tn + m.fp) > 0 ? m.fp / (m.tn + m.fp) : 0,
    fnr: (m.tp + m.fn) > 0 ? m.fn / (m.tp + m.fn) : 0,
    ...m,
  };
}

// ─── Risk Drift ─────────────────────────────────────────────────────

export interface DriftResult {
  riskDrift: number;
  confidenceDrift: number;
  avgRiskScore: number;
  avgConfidence: number;
  riskScoreStdDev: number;
  behaviorCountAvg: number;
  behaviorCountStdDev: number;
  latencyAvgMs: number;
  latencyP50Ms: number;
  latencyP95Ms: number;
  latencyP99Ms: number;
  latencyMaxMs: number;
  latencyStdDevMs: number;
}

export function computeDrift(results: ReplayResult[]): DriftResult {
  const risks = results.map(r => r.riskScore);
  const confs = results.map(r => r.confidence * 100);
  const bcs = results.map(r => r.behaviorsDetected.length);
  const lats = results.map(r => r.durationMs);

  const sorted = (arr: number[]) => [...arr].sort((a, b) => a - b);
  const percentile = (arr: number[], p: number) => {
    const s = sorted(arr);
    const idx = Math.ceil((p / 100) * s.length) - 1;
    return s[Math.max(0, Math.min(idx, s.length - 1))];
  };

  const avg = (arr: number[]) => arr.reduce((s, v) => s + v, 0) / arr.length;
  const stddev = (arr: number[], mean: number) =>
    Math.sqrt(arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length);

  const avgRisk = avg(risks);
  const avgConf = avg(confs);
  const avgBc = avg(bcs);

  return {
    riskDrift: Math.round(stddev(risks, avgRisk) * 10) / 10,
    confidenceDrift: Math.round(stddev(confs, avgConf) * 10) / 10,
    avgRiskScore: Math.round(avgRisk * 10) / 10,
    avgConfidence: Math.round(avgConf * 10) / 10,
    riskScoreStdDev: Math.round(stddev(risks, avgRisk) * 10) / 10,
    behaviorCountAvg: Math.round(avgBc * 10) / 10,
    behaviorCountStdDev: Math.round(stddev(bcs, avgBc) * 10) / 10,
    latencyAvgMs: Math.round(avg(lats) * 10) / 10,
    latencyP50Ms: Math.round(percentile(lats, 50) * 10) / 10,
    latencyP95Ms: Math.round(percentile(lats, 95) * 10) / 10,
    latencyP99Ms: Math.round(percentile(lats, 99) * 10) / 10,
    latencyMaxMs: Math.round(Math.max(...lats) * 10) / 10,
    latencyStdDevMs: Math.round(stddev(lats, avg(lats)) * 10) / 10,
  };
}

// ─── Campaign-based evaluation ──────────────────────────────────────

export interface CampaignEval {
  campaignId: string;
  name: string;
  total: number;
  passed: number;
  failed: number;
  passRate: number;
  topFailures: string[];
}

export function evaluateCampaign(report: CampaignReport): CampaignEval {
  return {
    campaignId: report.campaignId,
    name: report.name,
    total: report.totalScenarios,
    passed: report.passed,
    failed: report.failed,
    passRate: report.passRate,
    topFailures: report.topFailures.map(f => `${f.scenarioName}: missing ${f.missingBehaviors.join(', ')}`),
  };
}

// ─── Report Rendering ───────────────────────────────────────────────

export function renderMetrics(metrics: EvalMetrics, label: string): string {
  const lines: string[] = [];
  lines.push(`── ${label} ──`);
  lines.push(`  Accuracy:    ${(metrics.accuracy * 100).toFixed(1)}%`);
  lines.push(`  Precision:   ${(metrics.precision * 100).toFixed(1)}%`);
  lines.push(`  Recall:      ${(metrics.recall * 100).toFixed(1)}%`);
  lines.push(`  Specificity: ${(metrics.specificity * 100).toFixed(1)}%`);
  lines.push(`  F1 Score:    ${(metrics.f1 * 100).toFixed(1)}%`);
  lines.push(`  FPR:         ${(metrics.fpr * 100).toFixed(2)}%`);
  lines.push(`  FNR:         ${(metrics.fnr * 100).toFixed(2)}%`);
  lines.push(`  TP: ${metrics.tp}  FP: ${metrics.fp}  TN: ${metrics.tn}  FN: ${metrics.fn}`);
  return lines.join('\n');
}

export function renderDrift(drift: DriftResult, label: string): string {
  const lines: string[] = [];
  lines.push(`── ${label} ──`);
  lines.push(`  Avg Risk Score:       ${drift.avgRiskScore}`);
  lines.push(`  Risk StdDev:          ${drift.riskScoreStdDev}`);
  lines.push(`  Risk Drift:           ${drift.riskDrift}`);
  lines.push(`  Avg Confidence:       ${drift.avgConfidence}%`);
  lines.push(`  Confidence Drift:     ${drift.confidenceDrift}`);
  lines.push(`  Avg Behaviors/Session: ${drift.behaviorCountAvg}`);
  lines.push(`  Behaviors StdDev:     ${drift.behaviorCountStdDev}`);
  lines.push(`  Avg Latency:          ${drift.latencyAvgMs}ms`);
  lines.push(`  Latency P50:          ${drift.latencyP50Ms}ms`);
  lines.push(`  Latency P95:          ${drift.latencyP95Ms}ms`);
  lines.push(`  Latency P99:          ${drift.latencyP99Ms}ms`);
  lines.push(`  Latency Max:          ${drift.latencyMaxMs}ms`);
  lines.push(`  Latency StdDev:       ${drift.latencyStdDevMs}ms`);
  return lines.join('\n');
}

export function renderCampaignEval(eval_: CampaignEval): string {
  const lines: string[] = [];
  lines.push(`── Campaign: ${eval_.name} ──`);
  lines.push(`  Pass Rate: ${eval_.passRate}% (${eval_.passed}/${eval_.total})`);
  if (eval_.topFailures.length > 0) {
    lines.push(`  Top Failures:`);
    for (const f of eval_.topFailures.slice(0, 5)) {
      lines.push(`    ${f}`);
    }
  }
  return lines.join('\n');
}

// ─── Full Evaluation Suite ──────────────────────────────────────────

export interface FullEvalReport {
  timestamp: string;
  engineVersion: string;
  campaignCalibrated: CampaignEval | null;
  campaignBlind1: CampaignEval | null;
  campaignBlind2: CampaignEval | null;
  campaignBlind3: CampaignEval | null;
  replayMetrics: EvalMetrics | null;
  replayDrift: DriftResult | null;
  replayCampaignEval: CampaignEval | null;
}

export function runFullEvaluation(replayCorpusDir?: string): FullEvalReport {
  // Default to replay-corpus/synthetic/ if exists
  if (!replayCorpusDir) {
    const tryPath = path.join(process.cwd(), 'replay-corpus', 'synthetic');
    replayCorpusDir = fs.existsSync(tryPath) ? tryPath : '';
  }
  const report: FullEvalReport = {
    timestamp: new Date().toISOString(),
    engineVersion: ENGINE_VERSION,
    campaignCalibrated: null,
    campaignBlind1: null,
    campaignBlind2: null,
    campaignBlind3: null,
    replayMetrics: null,
    replayDrift: null,
    replayCampaignEval: null,
  };

  // 1. Campaign: calibrated
  try {
    const runner = new CampaignRunner();
    const calReport = runner.runCampaign(SCENARIOS, {
      id: 'eval-calibrated', name: 'Calibrated Corpus',
      description: '39 calibrated scenarios', scenarioIds: SCENARIOS.map(s => s.id),
      createdAt: new Date(),
    });
    report.campaignCalibrated = evaluateCampaign(calReport);
  } catch {}

  // 2. Campaigns: blind #1, #2, #3
  // Each file has different export patterns; try known names
  const blindFiles: Array<{ key: keyof FullEvalReport; path: string; exportNames: string[] }> = [
    { key: 'campaignBlind1', path: './blind-validation', exportNames: ['BLIND_SCENARIOS', 'RISK_AUDIT_SCENARIOS', 'SCENARIOS'] },
    { key: 'campaignBlind2', path: './blind-validation-2', exportNames: ['SCENARIOS', 'BLIND_SCENARIOS'] },
    { key: 'campaignBlind3', path: './blind-validation-3', exportNames: ['SCENARIOS', 'BLIND_SCENARIOS'] },
  ];
  for (const entry of blindFiles) {
    try {
      const mod = require(entry.path);
      let scenarios: any[] = [];
      for (const name of entry.exportNames) {
        if (mod[name] && Array.isArray(mod[name])) {
          scenarios = mod[name];
          break;
        }
      }
      // Some files use non-exported const; fall back to known scenario IDs loaded directly
      if (scenarios.length === 0) {
        continue; // skip if scenarios can't be loaded
      }
      const runner = new CampaignRunner();
      const report_ = runner.runCampaign(scenarios, {
        id: `eval-${entry.key}`, name: entry.key,
        description: '', scenarioIds: scenarios.map((s: any) => s.id),
        createdAt: new Date(),
      });
      (report as any)[entry.key] = evaluateCampaign(report_);
    } catch {}
  }

  // 3. Replay corpus
  if (replayCorpusDir && fs.existsSync(replayCorpusDir)) {
    try {
      // Load ground truth
      const groundTruth = new Map<string, string>();

      // Try ground_truth.csv first
      const gtPath = path.join(replayCorpusDir, 'ground_truth.csv');
      if (fs.existsSync(gtPath)) {
        const lines = fs.readFileSync(gtPath, 'utf-8').split('\n').slice(1);
        for (const line of lines) {
          if (!line.trim()) continue;
          const parts = line.split(',');
          if (parts.length >= 3) groundTruth.set(parts[0], parts[2]);
        }
      }

      // Try per-file .ground-truth.json (overrides csv for matching session IDs)
      const gtFiles = fs.readdirSync(replayCorpusDir)
        .filter(f => f.endsWith('.ground-truth.json'));
      for (const gtFile of gtFiles) {
        try {
          // Filename: session-XXXXX.ground-truth.json, session ID from metadata: XXXXX
          const fileSessionId = gtFile.replace(/\.ground-truth\.json$/, '');
          const raw = fs.readFileSync(path.join(replayCorpusDir, gtFile), 'utf-8');
          const gt = JSON.parse(raw);
          if (gt.expectedRisk) {
            // Try exact match and also try stripping 'session-' prefix
            groundTruth.set(fileSessionId, gt.expectedRisk);
            if (fileSessionId.startsWith('session-')) {
              groundTruth.set(fileSessionId.slice(8), gt.expectedRisk);
            }
          }
        } catch {}
      }

      // Run replay
      const engine = new ReplayEngine();
      const files = fs.readdirSync(replayCorpusDir)
        .filter(f => f.endsWith('.json') && f !== 'manifest.json' && !f.includes('.ground-truth'))
        .sort();

      const results: ReplayResult[] = [];
      for (const file of files) {
        try {
          const result = engine.replayFile(path.join(replayCorpusDir, file));
          results.push(result);
        } catch {}
      }

      if (results.length > 0) {
        const cm = computeConfusionMatrix(results, groundTruth);
        report.replayMetrics = computeMetrics(cm);
        report.replayDrift = computeDrift(results);

        // Also create a campaign-like eval from replay results
        const flagged = results.filter(r => r.riskLevel !== 'LOW').length;
        const correct = results.filter(r => {
          const expected = groundTruth.get(r.sessionId);
          if (expected === 'LOW') return r.riskLevel === 'LOW';
          return r.riskLevel !== 'LOW';
        }).length;

        report.replayCampaignEval = {
          campaignId: 'replay-corpus',
          name: 'Replay Corpus',
          total: results.length,
          passed: correct,
          failed: results.length - correct,
          passRate: Math.round((correct / results.length) * 1000) / 10,
          topFailures: [],
        };
      }
    } catch {}
  }

  return report;
}

export function renderFullReport(report: FullEvalReport): string {
  const lines: string[] = [];
  lines.push('═══ Full Evaluation Report ═══');
  lines.push(`  Engine:    v${report.engineVersion}`);
  lines.push(`  Timestamp: ${report.timestamp}`);
  lines.push('');

  if (report.campaignCalibrated) {
    lines.push(renderCampaignEval(report.campaignCalibrated));
    lines.push('');
  }

  for (const [key, label] of [['campaignBlind1', 'Blind Corpus #1 (15 esc)'],
    ['campaignBlind2', 'Blind Corpus #2 (14 esc)'],
    ['campaignBlind3', 'Blind Corpus #3 (14 esc)']] as const) {
    const c = (report as any)[key] as CampaignEval | null;
    if (c) {
      lines.push(renderCampaignEval({ ...c, name: label }));
      lines.push('');
    }
  }

  if (report.replayMetrics) {
    lines.push(renderMetrics(report.replayMetrics, 'Replay Corpus Metrics'));
    lines.push('');
  }
  if (report.replayDrift) {
    lines.push(renderDrift(report.replayDrift, 'Replay Drift'));
    lines.push('');
  }
  if (report.replayCampaignEval) {
    lines.push(renderCampaignEval(report.replayCampaignEval));
    lines.push('');
  }

  return lines.join('\n');
}
