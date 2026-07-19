'use strict';

import {
  NetworkFlow, Behavior, Evidence, RiskAssessment,
  SessionDna, Verdict, AntiEvasionSignal, EvidenceChain,
  AntiEvasionSignalType, CoverageInfo, HealthReport, RuntimeMetrics
} from './types';

export function buildSessionDna(
  sessionId: string,
  startTime: Date,
  flows: NetworkFlow[],
  behaviors: Behavior[],
  evidence: Evidence[],
  risk: RiskAssessment,
  antiEvasionSignals?: AntiEvasionSignal[],
  evidenceChains?: EvidenceChain[],
  coverageInfo?: CoverageInfo,
  healthReport?: HealthReport
): SessionDna {
  const endTime = new Date();
  const durationMs = endTime.getTime() - startTime.getTime();
  const uniqueHosts = [...new Set(
    flows.map(f => f.hostname).filter(Boolean) as string[]
  )];
  const totalBytesSent = flows.reduce((s, f) => s + f.bytesSent, 0);
  const totalBytesReceived = flows.reduce((s, f) => s + f.bytesReceived, 0);
  const repositoriesAccessed = extractRepos(flows, behaviors);

  const behaviorTypes = [...new Set(behaviors.map(b => b.type))];

  const topRiskFactor = risk.factors.length > 0
    ? risk.factors.sort((a, b) => b.contribution - a.contribution)[0].detail
    : 'No significant risk factors detected';

  const verdictSummary = buildVerdictSummary(risk, behaviors);

  const antiEvasionScore = antiEvasionSignals
    ? Math.min(100, Math.round(antiEvasionSignals.reduce((s, sig) => s + sig.score * sig.confidence, 0)))
    : 0;

  const antiEvasionSignalTypes: AntiEvasionSignalType[] = antiEvasionSignals
    ? [...new Set(antiEvasionSignals.map(s => s.type))]
    : [];

  const chainNames: string[] = evidenceChains
    ? evidenceChains.map(c => c.name)
    : [];

  const prepSignals: string[] = [];
  const procChains: string[] = [];
  for (const b of behaviors) {
    if (b.type === 'pre_operational_snapshot_detected' || b.type === 'preparation_detected') {
      prepSignals.push(...b.evidence);
    }
    if (b.type === 'process_chain_detected') {
      procChains.push(...b.evidence);
    }
  }

  const hasCanaryTrigger = behaviors.some(b =>
    b.type === 'canary_read' || b.type === 'canary_modified' ||
    b.type === 'canary_exfiltrated' || b.type === 'fake_secret_read' ||
    b.type === 'fake_secret_exfiltrated'
  );

  return {
    sessionId,
    startTime,
    endTime,
    durationMs,
    totalFlows: flows.length,
    totalBytesSent,
    totalBytesReceived,
    uniqueHosts,
    repositoriesAccessed,
    behaviors: behaviorTypes,
    topRiskFactor,
    riskScore: risk.score,
    riskLevel: risk.level,
    verdictSummary,
    confidence: computeOverallConfidence(behaviors, evidence),
    antiEvasionScore,
    antiEvasionSignals: antiEvasionSignalTypes,
    evidenceChains: chainNames,
    preparationSignals: prepSignals,
    processChains: procChains,
    hasCanaryTrigger,
    coverageScore: coverageInfo?.score ?? 0,
    healthStatus: healthReport?.status ?? 'healthy',
    metrics: healthReport?.metrics ?? {
      flowsReceived: 0, flowsDiscarded: 0, avgProcessTimeMs: 0,
      eventsPerSecond: 0, backpressure: false, bufferUsage: 0,
      peakMemoryMb: 0, queueDepth: 0, uptimeMs: 0,
    },
  };
}

function extractRepos(flows: NetworkFlow[], behaviors: Behavior[]): string[] {
  const repos = new Set<string>();
  for (const b of behaviors) {
    b.evidence.forEach(e => {
      const match = e.match(/repository[:\s]+([^\s,;]+)/i);
      if (match) repos.add(match[1]);
    });
  }
  return [...repos];
}

function buildVerdictSummary(
  risk: RiskAssessment, behaviors: Behavior[]
): string {
  if (behaviors.length === 0) {
    return 'No suspicious behavior detected during this session.';
  }

  const criticalBehaviors = behaviors.filter(b => {
    const criticalTypes = ['git_bundle_uploaded', 'secrets_exfiltrated', 'canary_exfiltrated', 'full_repo_snapshot'];
    return criticalTypes.includes(b.type);
  });

  if (criticalBehaviors.length > 0) {
    const details = criticalBehaviors.map(b => b.type.replace(/_/g, ' ')).join(', ');
    return `CRITICAL: ${details} detected. Evidence suggests repository exfiltration.`;
  }

  if (risk.level === 'HIGH') {
    return `HIGH RISK: Multiple suspicious behaviors detected. Review evidence for details.`;
  }

  if (risk.level === 'MEDIUM') {
    const types = [...new Set(behaviors.map(b => b.type))].join(', ');
    return `MEDIUM RISK: ${types}. Monitor closely.`;
  }

  return 'LOW RISK: Minor or no suspicious activity detected.';
}

function computeOverallConfidence(
  behaviors: Behavior[], evidence: Evidence[]
): number {
  if (behaviors.length === 0) return 1;
  const avgBehaviorConf = behaviors.reduce((s, b) => s + b.confidence, 0) / behaviors.length;
  const evidenceWeight = Math.min(evidence.length / 10, 1);
  return Math.min(avgBehaviorConf * 0.7 + evidenceWeight * 0.3 + 0.1, 0.99);
}

export function buildVerdict(
  sessionId: string, risk: RiskAssessment,
  behaviors: Behavior[], evidence: Evidence[],
  dna: SessionDna,
  confidenceScore?: number,
  coverageInfo?: CoverageInfo,
  healthAtEnd?: HealthReport
): Verdict {
  return {
    sessionId,
    overallRisk: risk,
    behaviors,
    evidence,
    sessionDna: dna,
    timestamp: new Date(),
    confidenceScore: confidenceScore ?? dna.confidence,
    coverageInfo: coverageInfo ?? { score: 0, sensors: [], totalActive: 0, totalConfigured: 0, blindSpots: [] },
    healthAtEnd: healthAtEnd ?? { status: 'healthy' as const, timestamp: new Date(), sensors: [], coverage: { score: 0, sensors: [], totalActive: 0, totalConfigured: 0, blindSpots: [] }, metrics: { flowsReceived: 0, flowsDiscarded: 0, avgProcessTimeMs: 0, eventsPerSecond: 0, backpressure: false, bufferUsage: 0, peakMemoryMb: 0, queueDepth: 0, uptimeMs: 0 } },
  };
}
