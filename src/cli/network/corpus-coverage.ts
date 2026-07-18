'use strict';

import * as fs from 'fs';
import * as path from 'path';
import * as child_process from 'child_process';
import { RecordedSession, EnvironmentDependency } from '../../core/network/types';
import { CANONICAL_PROFILES } from '../../core/network/canonical-sessions';

export interface CorpusCoverage {
  totalProfiles: number;
  captured: number;
  missing: string[];
  unavailable: string[];
  capturedList: string[];
  coveragePct: number;
  effectiveTotal: number;
  effectiveCaptured: number;
  effectiveCoveragePct: number;
  byCategory: Record<string, { total: number; captured: number }>;
  availableTools: string[];
}

export function detectAvailableTools(): string[] {
  const available: string[] = [];
  const checks: Array<{ tool: EnvironmentDependency; cmd: string }> = [
    { tool: 'docker', cmd: 'docker version' },
    { tool: 'go', cmd: 'go version' },
    { tool: 'terraform', cmd: 'terraform version' },
  ];
  for (const check of checks) {
    try {
      child_process.execSync(check.cmd, { encoding: 'utf-8', timeout: 3000, stdio: ['pipe', 'pipe', 'ignore'] });
      available.push(check.tool);
    } catch {}
  }
  return available;
}

export function computeCorpusCoverage(corpusDir: string, availableTools?: string[]): CorpusCoverage {
  const recordedDir = path.join(corpusDir, 'recorded');
  const capturedProfileIds = new Set<string>();
  const allSessionIds: string[] = [];

  if (fs.existsSync(recordedDir)) {
    const files = fs.readdirSync(recordedDir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const raw = fs.readFileSync(path.join(recordedDir, file), 'utf-8');
        const session: RecordedSession = JSON.parse(raw);
        if (session.metadata?.profile?.id) {
          capturedProfileIds.add(session.metadata.profile.id);
        }
        allSessionIds.push(session.metadata?.id ?? file);
      } catch {}
    }
  }

  const tools = availableTools ?? detectAvailableTools();

  const unavailable: string[] = [];
  const byCategory: Record<string, { total: number; captured: number }> = {};
  for (const p of CANONICAL_PROFILES) {
    if (!byCategory[p.category]) {
      byCategory[p.category] = { total: 0, captured: 0 };
    }
    if (p.requires && p.requires.some(r => !tools.includes(r))) {
      if (!capturedProfileIds.has(p.id)) {
        unavailable.push(p.id);
        continue;
      }
    }
    byCategory[p.category].total++;
    if (capturedProfileIds.has(p.id)) {
      byCategory[p.category].captured++;
    }
  }

  const missing = CANONICAL_PROFILES
    .filter(p => !capturedProfileIds.has(p.id) && !unavailable.includes(p.id))
    .map(p => p.id);

  const capturedList = CANONICAL_PROFILES
    .filter(p => capturedProfileIds.has(p.id))
    .map(p => p.id);

  const effectiveTotal = CANONICAL_PROFILES.length - unavailable.length;

  return {
    totalProfiles: CANONICAL_PROFILES.length,
    captured: capturedProfileIds.size,
    missing: missing.sort(),
    unavailable: unavailable.sort(),
    capturedList: capturedList.sort(),
    coveragePct: Math.round((capturedProfileIds.size / CANONICAL_PROFILES.length) * 1000) / 10,
    effectiveTotal,
    effectiveCaptured: capturedProfileIds.size,
    effectiveCoveragePct: effectiveTotal > 0
      ? Math.round((capturedProfileIds.size / effectiveTotal) * 1000) / 10
      : 0,
    byCategory,
    availableTools: tools,
  };
}

export function renderCorpusCoverage(coverage: CorpusCoverage): string {
  const lines: string[] = [];
  lines.push('═══ Corpus Coverage ═══');
  lines.push('');

  // Effective summary bar
  const barLen = 30;
  const filled = Math.round((coverage.effectiveCaptured / coverage.effectiveTotal) * barLen);
  const empty = barLen - filled;

  lines.push(`  Canonical profiles:       ${coverage.totalProfiles}`);
  lines.push(`  Unavailable (env-dep):    ${coverage.unavailable.length}`);
  lines.push(`  ─────────────────────────────────`);
  lines.push(`  Effective total:          ${coverage.effectiveTotal}`);
  lines.push(`  Captured:                 ${coverage.captured}`);
  lines.push(`  Missing (could capture):  ${coverage.missing.length}`);
  lines.push(`  Effective coverage:       ${coverage.effectiveCoveragePct}%`);
  lines.push(`                             [${'█'.repeat(filled)}${'░'.repeat(empty)}]`);
  lines.push('');

  // By category (effective)
  lines.push('  By category (effective coverage):');
  lines.push(`    ┌─────────────────┬────────┬──────────┐`);
  lines.push(`    │ Category         │  Cap/t │ %        │`);
  lines.push(`    ├─────────────────┼────────┼──────────┤`);

  // Count unavailable per category
  const unavailByCat: Record<string, number> = {};
  for (const id of coverage.unavailable) {
    const p = CANONICAL_PROFILES.find(pr => pr.id === id);
    const cat = p?.category ?? 'unknown';
    unavailByCat[cat] = (unavailByCat[cat] ?? 0) + 1;
  }

  const catOrder = ['benign', 'ia', 'suspicious', 'malicious'];
  for (const cat of catOrder) {
    const c = coverage.byCategory[cat];
    if (!c) continue;
    const effectiveCatTotal = c.total;
    const pct = effectiveCatTotal > 0 ? Math.round((c.captured / effectiveCatTotal) * 1000) / 10 : 0;
    const label = cat.charAt(0).toUpperCase() + cat.slice(1);
    const unavail = unavailByCat[cat] ?? 0;
    const suffix = unavail > 0 ? ` (${unavail} env-dep)` : '';
    lines.push(`    │ ${label.padEnd(15)} │  ${c.captured}/${String(effectiveCatTotal).padEnd(3)}│ ${pct.toFixed(1).padStart(6)}%${suffix} │`);
  }
  lines.push(`    └─────────────────┴────────┴──────────┘`);
  lines.push('');

  // Unavailable list
  if (coverage.unavailable.length > 0) {
    lines.push('  Unavailable (environment-dependent):');
    for (const id of coverage.unavailable) {
      const profile = CANONICAL_PROFILES.find(p => p.id === id);
      if (profile) {
        const deps = profile.requires?.join(', ') ?? '?';
        lines.push(`    [${profile.category.charAt(0).toUpperCase()}] ${id.padEnd(22)} ${profile.description}  (requires: ${deps})`);
      } else {
        lines.push(`    ${id}`);
      }
    }
    lines.push('  These profiles cannot be captured in the current environment.');
  }

  lines.push('');

  // Available tools
  if (coverage.availableTools.length > 0) {
    lines.push(`  Available tools: ${coverage.availableTools.join(', ')}`);
  }
  if (coverage.availableTools.length < 3) {
    const missingTools = ['docker', 'go', 'terraform'].filter(t => !coverage.availableTools.includes(t));
    lines.push(`  Missing tools:   ${missingTools.join(', ')}`);
  }
  lines.push('');

  // Missing list (actionable)
  if (coverage.missing.length > 0) {
    lines.push('  Missing profiles (could capture now):');
    for (const id of coverage.missing) {
      const profile = CANONICAL_PROFILES.find(p => p.id === id);
      if (profile) {
        lines.push(`    [${profile.category.charAt(0).toUpperCase()}] ${id.padEnd(22)} ${profile.description}`);
      } else {
        lines.push(`    ${id}`);
      }
    }
    lines.push('');
    lines.push(`  Record: sentinel network record --profile <id>`);
  } else {
    lines.push('  All capturable profiles captured!');
  }

  return lines.join('\n');
}
