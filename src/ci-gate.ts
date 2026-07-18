'use strict';

/**
 * CI Gate — regression check for all 4 corpus types.
 * Exit code 0 = pass, 1 = fail (regression detected).
 *
 * Usage: npx ts-node src/ci-gate.ts [--replay-dir <path>]
 */

import { runFullEvaluation, FullEvalReport, EvalMetrics, DriftResult, CampaignEval } from './core/network/evaluator';
import { recordBenchmark } from './core/network/benchmark-history';
import * as path from 'path';
import * as fs from 'fs';

interface GateThresholds {
  calibratedPassRateMin: number;  // 100%
  blindPassRateMin: number;       // 60% per corpus, not averaged
  replayAccuracyMin: number;      // 75%
  replayRecallMin: number;        // 95%
  replayFprMax: number;           // 70%
  replayFnrMax: number;           // 5%
}

const THRESHOLDS: GateThresholds = {
  calibratedPassRateMin: 100,
  blindPassRateMin: 60,
  replayAccuracyMin: 75,
  replayRecallMin: 95,
  replayFprMax: 70,
  replayFnrMax: 5,
};

interface GateResult {
  name: string;
  passed: boolean;
  actual: number;
  threshold: number;
  detail: string;
}

function checkCampaign(eval_: CampaignEval | null, name: string, minPassRate: number): GateResult {
  if (!eval_) {
    return { name, passed: false, actual: 0, threshold: minPassRate, detail: 'Could not evaluate' };
  }
  const passed = eval_.passRate >= minPassRate;
  return {
    name, passed,
    actual: eval_.passRate,
    threshold: minPassRate,
    detail: `${eval_.passed}/${eval_.total} (${eval_.passRate}%) — min ${minPassRate}%`,
  };
}

function checkMetric(metrics: EvalMetrics | null, name: string, actual: number, threshold: number, isMax: boolean): GateResult {
  if (!metrics) {
    return { name, passed: false, actual: 0, threshold, detail: 'No replay metrics available' };
  }
  const passed = isMax ? actual <= threshold : actual >= threshold;
  const cmp = isMax ? '≤' : '≥';
  const pct = (v: number) => `${(v * 100).toFixed(1)}%`;
  return {
    name, passed, actual: Math.round(actual * 1000) / 10,
    threshold, detail: `${pct(actual)} ${cmp} ${pct(threshold)}`,
  };
}

function runGate(replayCorpusDir?: string): void {
  console.log('═══ CI Gate: Regression Check ═══\n');
  const report = runFullEvaluation(replayCorpusDir);
  const results: GateResult[] = [];

  // 1. Calibrated corpus: must be 100%
  results.push(checkCampaign(report.campaignCalibrated, 'Calibrated Corpus', THRESHOLDS.calibratedPassRateMin));

  // 2. Blind corpuses: each independently >= threshold
  const blindLabels: Array<{ key: keyof FullEvalReport; label: string }> = [
    { key: 'campaignBlind1', label: 'Blind #1' },
    { key: 'campaignBlind2', label: 'Blind #2' },
    { key: 'campaignBlind3', label: 'Blind #3' },
  ];
  for (const { key, label } of blindLabels) {
    const e = (report as any)[key] as CampaignEval | null;
    if (e) {
      results.push(checkCampaign(e, label, THRESHOLDS.blindPassRateMin));
    }
  }

  // 3. Replay corpus metrics: Precision, F1, Accuracy, Recall, FPR, FNR
  if (report.replayMetrics) {
    results.push(checkMetric(report.replayMetrics, 'Replay Precision', report.replayMetrics.precision, THRESHOLDS.replayAccuracyMin / 100, false));
    results.push(checkMetric(report.replayMetrics, 'Replay F1 Score', report.replayMetrics.f1, THRESHOLDS.replayAccuracyMin / 100, false));
    results.push(checkMetric(report.replayMetrics, 'Replay Accuracy', report.replayMetrics.accuracy, THRESHOLDS.replayAccuracyMin / 100, false));
    results.push(checkMetric(report.replayMetrics, 'Replay Recall', report.replayMetrics.recall, THRESHOLDS.replayRecallMin / 100, false));
    results.push(checkMetric(report.replayMetrics, 'Replay FPR', report.replayMetrics.fpr, THRESHOLDS.replayFprMax / 100, true));
    results.push(checkMetric(report.replayMetrics, 'Replay FNR', report.replayMetrics.fnr, THRESHOLDS.replayFnrMax / 100, true));
  }

  // Print results
  let allPassed = true;
  for (const r of results) {
    const icon = r.passed ? '✓' : '✗';
    console.log(`  ${icon} ${r.name}: ${r.detail}`);
    if (!r.passed) allPassed = false;
  }

  // Record to benchmark history
  const benchmarkEntry = recordBenchmark(report);
  console.log(`\n  → Benchmark recorded: v${benchmarkEntry.engineVersion}`);

  console.log('');
  if (allPassed) {
    console.log('  All gates passed. No regressions detected.');
    process.exit(0);
  } else {
    console.log('  Some gates FAILED. Regression detected.');
    process.exit(1);
  }
}

// Parse args: default to replay-corpus/recorded/ with fallbacks
const replayDir = process.argv.includes('--replay-dir')
  ? process.argv[process.argv.indexOf('--replay-dir') + 1]
  : (() => {
      const candidates = [
        path.join(process.cwd(), 'replay-corpus', 'recorded'),
        path.join(process.cwd(), 'replay-corpus', 'synthetic'),
        path.join(process.cwd(), 'replay-corpus'),
      ];
      for (const d of candidates) {
        if (fs.existsSync(d)) return d;
      }
      return candidates[0];
    })();

runGate(replayDir);
