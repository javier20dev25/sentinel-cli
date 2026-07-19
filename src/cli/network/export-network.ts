'use strict';

import {
  NetworkAuditSession, SessionDna, Verdict,
  Behavior, Evidence, NetworkFlow
} from '../../core/network/types';

export function exportSessionJson(session: NetworkAuditSession): string {
  const verdict = session.verdict || null;
  return JSON.stringify({
    session: {
      id: session.id,
      startTime: session.startTime.toISOString(),
      endTime: session.endTime?.toISOString() || null,
      status: session.status,
      config: session.config,
    },
    summary: verdict ? exportDnaJson(verdict.sessionDna) : null,
    behaviors: session.behaviors.map(b => ({
      type: b.type,
      confidence: b.confidence,
      evidence: b.evidence,
      timestamp: b.timestamp.toISOString(),
    })),
    evidence: session.evidence.map(e => ({
      type: e.type,
      title: e.title,
      severity: e.severity,
      timestamp: e.timestamp.toISOString(),
    })),
    verdict: verdict ? {
      riskScore: verdict.overallRisk.score,
      riskLevel: verdict.overallRisk.level,
      summary: verdict.sessionDna.verdictSummary,
    } : null,
  }, null, 2);
}

export function exportDnaJson(dna: SessionDna): Record<string, unknown> {
  return {
    sessionId: dna.sessionId,
    durationMs: dna.durationMs,
    totalFlows: dna.totalFlows,
    totalBytesSent: dna.totalBytesSent,
    totalBytesReceived: dna.totalBytesReceived,
    uniqueHosts: dna.uniqueHosts,
    repositoriesAccessed: dna.repositoriesAccessed,
    behaviors: dna.behaviors,
    riskScore: dna.riskScore,
    riskLevel: dna.riskLevel,
    verdictSummary: dna.verdictSummary,
    confidence: dna.confidence,
  };
}

export function exportMarkdown(session: NetworkAuditSession): string {
  const verdict = session.verdict;
  const dna = verdict?.sessionDna;

  let md = `# Sentinel Network Audit Report\n\n`;
  md += `**Session:** \`${session.id}\`\n`;
  md += `**Date:** ${session.startTime.toISOString()}\n`;
  md += `**Duration:** ${session.endTime ? ((session.endTime.getTime() - session.startTime.getTime()) / 1000).toFixed(1) + 's' : 'running'}\n`;
  md += `**Status:** ${session.status}\n\n`;

  if (dna) {
    md += `## Risk Assessment\n\n`;
    md += `| Metric | Value |\n`;
    md += `|--------|-------|\n`;
    md += `| Risk Level | ${dna.riskLevel} |\n`;
    md += `| Risk Score | ${dna.riskScore}/100 |\n`;
    md += `| Confidence | ${(dna.confidence * 100).toFixed(0)}% |\n`;
    md += `| Flows | ${dna.totalFlows} |\n`;
    md += `| Hosts | ${dna.uniqueHosts.join(', ')} |\n\n`;

    md += `## Verdict\n\n${dna.verdictSummary}\n\n`;
  }

  if (session.behaviors.length > 0) {
    md += `## Detected Behaviors\n\n`;
    md += `| Type | Confidence | Evidence |\n`;
    md += `|------|-----------|----------|\n`;
    for (const b of session.behaviors) {
      md += `| ${b.type.replace(/_/g, ' ')} | ${(b.confidence * 100).toFixed(0)}% | ${b.evidence.join('; ')} |\n`;
    }
    md += '\n';
  }

  if (session.evidence.length > 0) {
    md += `## Evidence\n\n`;
    md += `| Time | Type | Title | Severity |\n`;
    md += `|------|------|-------|----------|\n`;
    for (const e of session.evidence) {
      md += `| ${e.timestamp.toLocaleTimeString()} | ${e.type} | ${e.title} | ${e.severity} |\n`;
    }
    md += '\n';
  }

  return md;
}
