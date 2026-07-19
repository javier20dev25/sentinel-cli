'use strict';

import {
  NetworkAuditSession, NetworkFlow, Behavior, Evidence,
  SessionDna, Verdict, BlindSpotEntry, CampaignReport, CampaignResult
} from '../../core/network/types';

export function renderSessionStatus(session: NetworkAuditSession): string {
  const lines: string[] = [];
  const dur = session.endTime
    ? ((session.endTime.getTime() - session.startTime.getTime()) / 1000).toFixed(0)
    : ((Date.now() - session.startTime.getTime()) / 1000).toFixed(0);

  lines.push('');
  lines.push('╔══════════════════════════════════════════╗');
  lines.push('║        NETWORK AUDITOR                  ║');
  lines.push('╠══════════════════════════════════════════╣');
  lines.push(`║  Status: ${session.status.padEnd(30)} ║`);
  lines.push(`║  Duration: ${dur.padEnd(5)}s             ║`);
  lines.push(`║  Flows: ${String(session.flows.length).padEnd(28)} ║`);
  lines.push(`║  Behaviors: ${String(session.behaviors.length).padEnd(24)} ║`);
  lines.push(`║  Evidence: ${String(session.evidence.length).padEnd(25)} ║`);
  lines.push('╚══════════════════════════════════════════╝');
  lines.push('  Keys: [S]top  [H]istory  [Q]uit');
  return lines.join('\n');
}

export function renderFlow(flow: NetworkFlow): string {
  const ts = flow.timestamp.toLocaleTimeString();
  const dest = flow.hostname || flow.destAddr || 'unknown';
  const sentKB = (flow.bytesSent / 1024).toFixed(1);
  const recvKB = (flow.bytesReceived / 1024).toFixed(1);
  const icon = getFlowIcon(flow);
  return `${icon} ${ts} ${flow.protocol} ${dest} ↓${sentKB}KB ↑${recvKB}KB`;
}

function getFlowIcon(flow: NetworkFlow): string {
  const suspiciousHosts = ['.grok.com', '.x.ai', '.openai.com', '.anthropic.com',
    '.googleapis.com', 'storage.googleapis.com', '.cursor.sh'];
  if (flow.hostname && suspiciousHosts.some(h => flow.hostname!.includes(h))) {
    return '⚠';
  }
  if (flow.bytesSent > 1048576) return '▲';
  return '·';
}

export function renderBehavior(behavior: Behavior): string {
  const ts = behavior.timestamp.toLocaleTimeString();
  const type = behavior.type.replace(/_/g, ' ');
  const conf = (behavior.confidence * 100).toFixed(0);
  return `  [${conf}%] ${ts} ${type}`;
}

export function renderEvidenceItem(evidence: Evidence): string {
  const icon = evidence.severity === 'critical' ? '!' :
               evidence.severity === 'warning' ? '?' : ' ';
  return `  ${icon} ${evidence.title}`;
}

export function renderVerdict(verdict: Verdict): string {
  const dna = verdict.sessionDna;
  const lines: string[] = [];
  lines.push('');
  lines.push('╔══════════════════════════════════════════════════════╗');
  lines.push('║            SESSION VERDICT                          ║');
  lines.push('╠══════════════════════════════════════════════════════╣');
  lines.push(`║  Risk: ${dna.riskLevel.padEnd(38)} ║`);
  lines.push(`║  Score: ${String(dna.riskScore).padEnd(37)} ║`);
  lines.push(`║  Duration: ${(dna.durationMs / 1000).toFixed(1)}s ${''.padEnd(30)} ║`);
  lines.push(`║  Flows: ${String(dna.totalFlows).padEnd(37)} ║`);
  lines.push(`║  Hosts: ${dna.uniqueHosts.join(', ').substring(0, 35).padEnd(37)} ║`);
  lines.push(`║  Behaviors: ${dna.behaviors.length + ' ' + dna.behaviors.slice(0, 3).map(b => b.replace(/_/g, ' ')).join(', ').substring(0, 32).padEnd(32)} ║`);
  lines.push(`║  Confidence: ${(dna.confidence * 100).toFixed(0)}% ${''.padEnd(30)} ║`);
  lines.push('╠══════════════════════════════════════════════════════╣');
  lines.push(`║  ${dna.verdictSummary.substring(0, 48).padEnd(48)} ║`);
  if (dna.verdictSummary.length > 48) {
    lines.push(`║  ${dna.verdictSummary.substring(48, 96).padEnd(48)} ║`);
  }
  lines.push('╚══════════════════════════════════════════════════════╝');
  return lines.join('\n');
}

export function renderSessionHistory(
  sessions: Array<{ id: string; start_time: string; end_time: string; status: string; risk_level?: string; risk_score?: number }>
): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('Sessions:');
  lines.push('─'.repeat(80));
  for (const s of sessions) {
    const start = new Date(s.start_time).toLocaleString();
    const end = s.end_time ? new Date(s.end_time).toLocaleString() : 'running';
    const risk = s.risk_level || '-';
    const score = s.risk_score !== undefined ? String(s.risk_score) : '-';
    lines.push(`  ${s.id.substring(0, 20).padEnd(22)} ${start.padEnd(20)} ${risk.padEnd(8)} ${score.padEnd(5)} ${s.status}`);
  }
  return lines.join('\n');
}

export function renderDnaSummary(dna: SessionDna): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('Session DNA:');
  lines.push('─'.repeat(60));
  lines.push(`  Risk Level:    ${dna.riskLevel} (${dna.riskScore}/100)`);
  lines.push(`  Confidence:    ${(dna.confidence * 100).toFixed(0)}%`);
  lines.push(`  Duration:      ${(dna.durationMs / 1000).toFixed(1)}s`);
  lines.push(`  Flows:         ${dna.totalFlows}`);
  lines.push(`  Data Sent:     ${(dna.totalBytesSent / 1024 / 1024).toFixed(2)} MB`);
  lines.push(`  Data Received: ${(dna.totalBytesReceived / 1024 / 1024).toFixed(2)} MB`);
  lines.push(`  Unique Hosts:  ${dna.uniqueHosts.join(', ')}`);
  lines.push(`  Behaviors:     ${dna.behaviors.map(b => b.replace(/_/g, ' ')).join(', ')}`);
  lines.push(`  Top Risk:      ${dna.topRiskFactor}`);
  lines.push('');
  lines.push(`  Summary: ${dna.verdictSummary}`);
  return lines.join('\n');
}

export function renderBlindSpotEntry(bs: BlindSpotEntry): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(`  [${bs.severity.toUpperCase()}] ${bs.title}`);
  lines.push(`  ${'─'.repeat(50)}`);
  lines.push(`  ID:       ${bs.id}`);
  lines.push(`  Status:   ${bs.status}`);
  lines.push(`  Sensor:   ${bs.sensorFailed}`);
  lines.push(`  Impact:   ${bs.impact}`);
  lines.push(`  When:     ${bs.createdAt.toLocaleString()}`);
  if (bs.sessionId) lines.push(`  Session:  ${bs.sessionId}`);
  lines.push('');
  lines.push(`  What happened:`);
  lines.push(`  ${bs.howItHappened}`);
  lines.push('');
  lines.push(`  Expected: ${bs.expectedBehavior}`);
  lines.push(`  Actual:   ${bs.actualObservation}`);
  if (bs.description) {
    lines.push('');
    lines.push(`  Notes: ${bs.description}`);
  }
  if (bs.resolution) {
    lines.push('');
    lines.push(`  Resolution: ${bs.resolution}`);
  }
  return lines.join('\n');
}

export function renderBlindSpotLog(
  entries: BlindSpotEntry[],
  stats?: { total: number; open: number; resolved: number; bySeverity: Array<{ severity: string; count: number }>; bySensor: Array<{ sensor_failed: string; count: number }> }
): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('╔══════════════════════════════════════════════════════╗');
  lines.push('║              BLIND SPOT LOG                        ║');
  lines.push('╠══════════════════════════════════════════════════════╣');

  if (stats) {
    lines.push(`║  Total: ${String(stats.total).padEnd(37)} ║`);
    lines.push(`║  Open: ${String(stats.open).padEnd(38)} ║`);
    lines.push(`║  Resolved: ${String(stats.resolved).padEnd(33)} ║`);
    if (stats.bySeverity.length > 0) {
      const sev = stats.bySeverity.map(s => `${s.severity}:${s.count}`).join(', ');
      lines.push(`║  By severity: ${sev.substring(0, 37).padEnd(37)} ║`);
    }
    if (stats.bySensor.length > 0) {
      const sen = stats.bySensor.slice(0, 3).map(s => `${s.sensor_failed}:${s.count}`).join(', ');
      lines.push(`║  Top sensors: ${sen.substring(0, 37).padEnd(37)} ║`);
    }
  }
  lines.push('╚══════════════════════════════════════════════════════╝');

  if (entries.length === 0) {
    lines.push('\n  No blind spots registered yet.');
    lines.push('  Use: sentinel network blindspots add');
    return lines.join('\n');
  }

  for (const bs of entries) {
    lines.push('');
    lines.push(`  ${severityIcon(bs.severity)} [${bs.status}] ${bs.title}`);
    lines.push(`  Sensor: ${bs.sensorFailed} | Impact: ${bs.impact}`);
    lines.push(`  ${bs.howItHappened.substring(0, 70)}`);
    lines.push(`  ID: ${bs.id} | ${bs.createdAt.toLocaleDateString()}`);
  }
  return lines.join('\n');
}

export function renderCampaignReport(report: CampaignReport): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('╔══════════════════════════════════════════════════════════════╗');
  lines.push('║              VALIDATION CAMPAIGN REPORT                    ║');
  lines.push('╠══════════════════════════════════════════════════════════════╣');
  lines.push(`║  Campaign: ${report.name.padEnd(57)} ║`);
  lines.push(`║  Scenarios: ${String(report.totalScenarios).padEnd(53)} ║`);
  lines.push(`║  Passed: ${String(report.passed).padEnd(56)} ║`);
  lines.push(`║  Failed: ${String(report.failed).padEnd(56)} ║`);
  lines.push(`║  Pass Rate: ${String(report.passRate).padEnd(10)}%              ║`);
  lines.push(`║  Duration: ${(report.durationMs / 1000).toFixed(1)}s${''.padEnd(27)} ║`);
  lines.push('╠══════════════════════════════════════════════════════════════╣');
  lines.push(`║  Avg Risk Score:   ${String(report.avgRiskScore).padEnd(45)} ║`);
  lines.push(`║  Avg Confidence:   ${String(report.avgConfidence).padEnd(45)} ║`);
  lines.push(`║  Avg Coverage:     ${String(report.avgCoverage).padEnd(10)}%                ║`);
  lines.push('╚══════════════════════════════════════════════════════════════╝');

  if (report.topFailures.length > 0) {
    lines.push('\nTop Failures:');
    lines.push('─'.repeat(70));
    for (const f of report.topFailures) {
      lines.push(`  ! ${f.scenarioName}`);
      if (f.missingBehaviors.length > 0) {
        lines.push(`    Missing: ${f.missingBehaviors.join(', ')}`);
      }
      if (f.unexpectedBehaviors.length > 0) {
        lines.push(`    Unexpected: ${f.unexpectedBehaviors.join(', ')}`);
      }
    }
  }

  if (report.results.length <= 20) {
    lines.push('\nPer-Scenario Results:');
    lines.push('─'.repeat(70));
    for (const r of report.results) {
      const icon = r.passed ? '✓' : '✗';
      const level = r.riskLevel.padEnd(8);
      const conf = (r.confidenceScore * 100).toFixed(0).padStart(3);
      const cov = r.coverageScore.toFixed(1).padStart(5);
      lines.push(`  ${icon} ${r.scenarioName.padEnd(32)} ${level} conf:${conf}% cov:${cov}%`);
    }
  }

  lines.push('');
  return lines.join('\n');
}

function severityIcon(severity: string): string {
  switch (severity) {
    case 'critical': return '!!';
    case 'high': return '!';
    case 'medium': return '?';
    case 'low': return '·';
    default: return ' ';
  }
}
