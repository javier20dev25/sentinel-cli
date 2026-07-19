'use strict';

import * as fs from 'fs';
import * as path from 'path';
import { FullEvalReport, EvalMetrics, CampaignEval } from './evaluator';
import { ENGINE_VERSION } from './version';

export interface BenchmarkEntry {
  engineVersion: string;
  timestamp: string;
  calibrated: { passed: number; total: number; passRate: number } | null;
  blind: Array<{ name: string; passed: number; total: number; passRate: number }>;
  replay: {
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    fpr: number;
    fnr: number;
    tp: number;
    fp: number;
    tn: number;
    fn: number;
    latencyAvgMs: number;
    latencyP50Ms: number;
    latencyP95Ms: number;
    latencyP99Ms: number;
    latencyMaxMs: number;
    latencyStdDevMs: number;
  } | null;
}

const HISTORY_FILE = path.join(process.cwd(), 'benchmark-history.json');

function loadHistory(): BenchmarkEntry[] {
  try {
    if (fs.existsSync(HISTORY_FILE)) {
      const raw = fs.readFileSync(HISTORY_FILE, 'utf-8');
      return JSON.parse(raw);
    }
  } catch {}
  return [];
}

function saveHistory(history: BenchmarkEntry[]): void {
  fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2), 'utf-8');
}

export function recordBenchmark(report: FullEvalReport): BenchmarkEntry {
  const history = loadHistory();

  const blind: BenchmarkEntry['blind'] = [];
  const blindLabels = ['campaignBlind1', 'campaignBlind2', 'campaignBlind3'];
  const blindNames = ['Blind #1', 'Blind #2', 'Blind #3'];
  for (let i = 0; i < blindLabels.length; i++) {
    const c = (report as any)[blindLabels[i]] as CampaignEval | null;
    if (c) {
      blind.push({ name: blindNames[i], passed: c.passed, total: c.total, passRate: c.passRate });
    }
  }

  const entry: BenchmarkEntry = {
    engineVersion: report.engineVersion,
    timestamp: report.timestamp,
    calibrated: report.campaignCalibrated
      ? { passed: report.campaignCalibrated.passed, total: report.campaignCalibrated.total, passRate: report.campaignCalibrated.passRate }
      : null,
    blind,
    replay: report.replayMetrics
      ? {
          accuracy: report.replayMetrics.accuracy,
          precision: report.replayMetrics.precision,
          recall: report.replayMetrics.recall,
          f1: report.replayMetrics.f1,
          fpr: report.replayMetrics.fpr,
          fnr: report.replayMetrics.fnr,
          tp: report.replayMetrics.tp,
          fp: report.replayMetrics.fp,
          tn: report.replayMetrics.tn,
          fn: report.replayMetrics.fn,
          latencyAvgMs: report.replayDrift?.latencyAvgMs ?? 0,
          latencyP50Ms: report.replayDrift?.latencyP50Ms ?? 0,
          latencyP95Ms: report.replayDrift?.latencyP95Ms ?? 0,
          latencyP99Ms: report.replayDrift?.latencyP99Ms ?? 0,
          latencyMaxMs: report.replayDrift?.latencyMaxMs ?? 0,
          latencyStdDevMs: report.replayDrift?.latencyStdDevMs ?? 0,
        }
      : null,
  };

  // Replace last entry with same version, or append
  const existingIdx = history.findIndex(e => e.engineVersion === entry.engineVersion);
  if (existingIdx >= 0) {
    history[existingIdx] = entry;
  } else {
    history.push(entry);
  }

  saveHistory(history);
  return entry;
}

function fmtPct(v: number | undefined, decimals: number = 1): string {
  return v !== undefined ? `${v.toFixed(decimals)}` : '—';
}

function pctChange(current: number | undefined, prev: number | undefined): string {
  if (current === undefined || prev === undefined || prev === 0) return '  —';
  const delta = ((current - prev) / prev) * 100;
  return delta >= 0 ? ` +${delta.toFixed(1)}%` : ` ${delta.toFixed(1)}%`;
}

function msChange(current: number | undefined, prev: number | undefined): string {
  if (current === undefined || prev === undefined) return '  —';
  const delta = current - prev;
  return delta >= 0 ? ` +${delta.toFixed(1)}` : ` ${delta.toFixed(1)}`;
}

export function renderBenchmarkHistory(): string {
  const history = loadHistory();
  if (history.length === 0) return 'No benchmark history found.';

  const lines: string[] = [];
  lines.push('═══ Benchmark History ═══');
  lines.push('');

  // Header
  const cols = ['Version', 'Date', 'Cal%', 'B1%', 'B2%', 'B3%', 'Acc', 'Prec', 'Rec', 'F1', 'FPR', 'FNR'];
  lines.push('  ' + cols.map(c => c.padEnd(8)).join(''));
  lines.push('  ' + '─'.repeat(cols.length * 9));

  for (const e of history) {
    const date = e.timestamp.substring(0, 10);
    const cal = e.calibrated ? `${e.calibrated.passRate.toFixed(1)}` : '—';
    const b1 = e.blind[0] ? `${e.blind[0].passRate.toFixed(1)}` : '—';
    const b2 = e.blind[1] ? `${e.blind[1].passRate.toFixed(1)}` : '—';
    const b3 = e.blind[2] ? `${e.blind[2].passRate.toFixed(1)}` : '—';
    const r = e.replay;
    const acc = r ? `${(r.accuracy * 100).toFixed(1)}` : '—';
    const prec = r ? `${(r.precision * 100).toFixed(1)}` : '—';
    const rec = r ? `${(r.recall * 100).toFixed(1)}` : '—';
    const f1 = r ? `${(r.f1 * 100).toFixed(1)}` : '—';
    const fpr = r ? `${(r.fpr * 100).toFixed(1)}` : '—';
    const fnr = r ? `${(r.fnr * 100).toFixed(1)}` : '—';

    lines.push(`  ${e.engineVersion.padEnd(8)} ${date.padEnd(10)} ${cal.padEnd(7)} ${b1.padEnd(7)} ${b2.padEnd(7)} ${b3.padEnd(7)} ${acc.padEnd(7)} ${prec.padEnd(7)} ${rec.padEnd(7)} ${f1.padEnd(7)} ${fpr.padEnd(7)} ${fnr.padEnd(7)}`);
  }

  // Delta comparison with previous version
  if (history.length >= 2) {
    const cur = history[history.length - 1];
    const prev = history[history.length - 2];
    const cr = cur.replay;
    const pr = prev.replay;

    lines.push('');
    lines.push(`Δ vs ${prev.engineVersion}:`);
    lines.push(`  ┌─────────────────┬───────────┬───────────┐`);
    lines.push(`  │ Metric           │ ${prev.engineVersion.padEnd(9)}│ ${cur.engineVersion.padEnd(9)}│`);
    lines.push(`  ├─────────────────┼───────────┼───────────┤`);
    lines.push(`  │ Calibrated       │ ${fmtPct(prev.calibrated?.passRate).padEnd(9)}│ ${fmtPct(cur.calibrated?.passRate).padEnd(9)}│`);
    lines.push(`  │ Blind #1         │ ${fmtPct(prev.blind[0]?.passRate).padEnd(9)}│ ${fmtPct(cur.blind[0]?.passRate).padEnd(9)}│`);
    lines.push(`  │ Blind #2         │ ${fmtPct(prev.blind[1]?.passRate).padEnd(9)}│ ${fmtPct(cur.blind[1]?.passRate).padEnd(9)}│`);
    lines.push(`  │ Blind #3         │ ${fmtPct(prev.blind[2]?.passRate).padEnd(9)}│ ${fmtPct(cur.blind[2]?.passRate).padEnd(9)}│`);

    if (cr && pr) {
      lines.push(`  ├─────────────────┼───────────┼───────────┤`);
      lines.push(`  │ Accuracy         │ ${(pr.accuracy * 100).toFixed(1).padEnd(9)}│ ${(cr.accuracy * 100).toFixed(1).padEnd(9)}│`);
      lines.push(`  │ Precision        │ ${(pr.precision * 100).toFixed(1).padEnd(9)}│ ${(cr.precision * 100).toFixed(1).padEnd(9)}│`);
      lines.push(`  │ Recall           │ ${(pr.recall * 100).toFixed(1).padEnd(9)}│ ${(cr.recall * 100).toFixed(1).padEnd(9)}│`);
      lines.push(`  │ F1               │ ${(pr.f1 * 100).toFixed(1).padEnd(9)}│ ${(cr.f1 * 100).toFixed(1).padEnd(9)}│`);
      lines.push(`  │ FPR              │ ${(pr.fpr * 100).toFixed(1).padEnd(9)}│ ${(cr.fpr * 100).toFixed(1).padEnd(9)}│`);
      lines.push(`  │ FNR              │ ${(pr.fnr * 100).toFixed(1).padEnd(9)}│ ${(cr.fnr * 100).toFixed(1).padEnd(9)}│`);
      lines.push(`  ├─────────────────┼───────────┼───────────┤`);
      lines.push(`  │ Latency Avg (ms) │ ${pr.latencyAvgMs.toFixed(1).padEnd(9)}│ ${cr.latencyAvgMs.toFixed(1).padEnd(9)}│`);
      lines.push(`  │ Latency P50 (ms) │ ${pr.latencyP50Ms.toFixed(1).padEnd(9)}│ ${cr.latencyP50Ms.toFixed(1).padEnd(9)}│`);
      lines.push(`  │ Latency P95 (ms) │ ${pr.latencyP95Ms.toFixed(1).padEnd(9)}│ ${cr.latencyP95Ms.toFixed(1).padEnd(9)}│`);
      lines.push(`  │ Latency P99 (ms) │ ${pr.latencyP99Ms.toFixed(1).padEnd(9)}│ ${cr.latencyP99Ms.toFixed(1).padEnd(9)}│`);
      lines.push(`  │ Latency Max (ms) │ ${pr.latencyMaxMs.toFixed(1).padEnd(9)}│ ${cr.latencyMaxMs.toFixed(1).padEnd(9)}│`);
      lines.push(`  │ Latency SD (ms)  │ ${pr.latencyStdDevMs.toFixed(1).padEnd(9)}│ ${cr.latencyStdDevMs.toFixed(1).padEnd(9)}│`);
    }

    lines.push(`  └─────────────────┴───────────┴───────────┘`);
  }

  return lines.join('\n');
}

export function getBenchmarkHistory(): BenchmarkEntry[] {
  return loadHistory();
}
