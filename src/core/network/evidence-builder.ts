'use strict';

import {
  NetworkFlow, ProcessEvent, FileAccessEvent, GitCommandEvent,
  Behavior, Artifact, Evidence, EvidenceType, RiskAssessment, generateId
} from './types';

export function buildFlowEvidence(
  flow: NetworkFlow, sessionId: string
): Evidence {
  return {
    id: generateId(),
    sessionId,
    flowId: flow.id,
    type: 'connection_log',
    title: `${flow.protocol} connection to ${flow.hostname || flow.destAddr}`,
    description: `${flow.protocol} ${flow.method || ''} ${flow.path || ''} → ${flow.hostname || flow.destAddr}:${flow.destPort} (${(flow.bytesSent / 1024).toFixed(1)}KB sent, ${(flow.bytesReceived / 1024).toFixed(1)}KB received)`,
    data: {
      protocol: flow.protocol,
      hostname: flow.hostname,
      destAddr: flow.destAddr,
      destPort: flow.destPort,
      bytesSent: flow.bytesSent,
      bytesReceived: flow.bytesReceived,
      durationMs: flow.durationMs,
      tlsVersion: flow.tlsVersion,
      sni: flow.sni,
      method: flow.method,
      path: flow.path,
    },
    timestamp: flow.timestamp,
    severity: classifyFlowSeverity(flow),
  };
}

function classifyFlowSeverity(flow: NetworkFlow): 'info' | 'warning' | 'critical' {
  if (flow.bytesSent > 10485760) return 'critical';
  if (flow.bytesSent > 1048576) return 'warning';
  if (flow.hostname && isSuspiciousHost(flow.hostname)) return 'warning';
  return 'info';
}

function isSuspiciousHost(hostname: string): boolean {
  const patterns = [
    '.grok.com', '.x.ai', '.openai.com', '.anthropic.com',
    '.googleapis.com', 'storage.googleapis.com',
    '.cursor.sh', '.claude.ai',
  ];
  return patterns.some(p => hostname.includes(p));
}

export function buildProcessEvidence(
  proc: ProcessEvent, sessionId: string
): Evidence {
  return {
    id: generateId(),
    sessionId,
    type: 'process_log',
    title: `Process: ${proc.name} (PID ${proc.pid})`,
    description: `${proc.name} executed: ${proc.commandLine.substring(0, 200)}`,
    data: {
      pid: proc.pid,
      name: proc.name,
      commandLine: proc.commandLine,
      parentPid: proc.parentPid,
      username: proc.username,
      riskIndicators: proc.riskIndicators,
    },
    timestamp: proc.timestamp,
    severity: proc.riskIndicators.length > 0 ? 'warning' : 'info',
  };
}

export function buildFileAccessEvidence(
  access: FileAccessEvent, sessionId: string
): Evidence {
  return {
    id: generateId(),
    sessionId,
    type: 'file_access_log',
    title: `File ${access.operation}: ${access.filePath}`,
    description: `${access.processName} (PID ${access.pid}) performed ${access.operation} on ${access.filePath}`,
    data: {
      filePath: access.filePath,
      processName: access.processName,
      pid: access.pid,
      operation: access.operation,
      bytesRead: access.bytesRead,
    },
    timestamp: access.timestamp,
    severity: isSensitiveGitPath(access.filePath) ? 'warning' : 'info',
  };
}

function isSensitiveGitPath(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return lower.includes('.git/objects') ||
         lower.includes('.git/logs') ||
         lower.includes('.git/config') ||
         lower.endsWith('.bundle');
}

export function buildGitCommandEvidence(
  cmd: GitCommandEvent, sessionId: string
): Evidence {
  return {
    id: generateId(),
    sessionId,
    type: 'git_command_log',
    title: `Git command: ${cmd.action}`,
    description: `${cmd.processName} executed: ${cmd.commandLine.substring(0, 200)}`,
    data: {
      pid: cmd.pid,
      processName: cmd.processName,
      commandLine: cmd.commandLine,
      action: cmd.action,
      repository: cmd.repository,
    },
    timestamp: cmd.timestamp,
    severity: isDangerousGitAction(cmd.action) ? 'critical' : 'warning',
  };
}

function isDangerousGitAction(action: string): boolean {
  return ['bundle', 'archive', 'pack'].includes(action);
}

export function buildBehaviorEvidence(
  behavior: Behavior, sessionId: string
): Evidence {
  return {
    id: generateId(),
    sessionId,
    behaviorId: behavior.id,
    type: 'behavior_classification',
    title: `Behavior: ${behavior.type.replace(/_/g, ' ')}`,
    description: `Confidence: ${(behavior.confidence * 100).toFixed(0)}% | ${behavior.evidence.join('; ')}`,
    data: {
      behaviorType: behavior.type,
      confidence: behavior.confidence,
      source: behavior.source,
      evidence: behavior.evidence,
      artifactCount: behavior.artifacts.length,
    },
    timestamp: behavior.timestamp,
    severity: classifyBehaviorSeverity(behavior.type),
  };
}

function classifyBehaviorSeverity(type: string): 'info' | 'warning' | 'critical' {
  const critical = ['git_bundle_uploaded', 'secrets_exfiltrated', 'canary_exfiltrated', 'full_repo_snapshot'];
  const warning = ['git_bundle_created', 'git_archive_created', 'git_history_read', 'git_objects_read', 'code_upload', 'prompt_injection_attempt', 'suspicious_connection'];
  if (critical.includes(type)) return 'critical';
  if (warning.includes(type)) return 'warning';
  return 'info';
}

export function buildAntiEvasionEvidence(
  signal: { type: string; score: number; confidence: number; evidence: string[]; details: Record<string, unknown>; timestamp: Date; id: string },
  sessionId: string
): Evidence {
  return {
    id: signal.id || generateId(),
    sessionId,
    type: 'behavior_classification',
    title: `Anti-evasion signal: ${signal.type.replace(/_/g, ' ')}`,
    description: `Score: ${signal.score} | ${signal.evidence.join('; ')}`,
    data: {
      signalType: signal.type,
      score: signal.score,
      confidence: signal.confidence,
      evidence: signal.evidence,
      details: signal.details,
    },
    timestamp: signal.timestamp,
    severity: signal.score >= 30 ? 'critical' : signal.score >= 15 ? 'warning' : 'info',
  };
}

export function buildChainEvidence(
  chain: { id: string; name: string; confidence: number; steps: Array<{ type: string; description: string }>; summary: string; timestamp: Date },
  sessionId: string
): Evidence {
  return {
    id: chain.id || generateId(),
    sessionId,
    type: 'behavior_classification',
    title: `Evidence chain: ${chain.name.replace(/_/g, ' ')}`,
    description: chain.summary,
    data: {
      chainName: chain.name,
      confidence: chain.confidence,
      steps: chain.steps.map(s => ({ type: s.type, description: s.description })),
      summary: chain.summary,
    },
    timestamp: chain.timestamp,
    severity: chain.confidence >= 0.8 ? 'critical' : 'warning',
  };
}

export function buildRiskEvidence(
  risk: RiskAssessment, sessionId: string
): Evidence {
  const topFactors = risk.factors
    .sort((a, b) => b.contribution - a.contribution)
    .slice(0, 3);

  return {
    id: generateId(),
    sessionId,
    type: 'risk_calculation',
    title: `Risk assessment: ${risk.level} (${risk.score}/100)`,
    description: `Top factors: ${topFactors.map(f => f.detail).join(' | ')}`,
    data: {
      score: risk.score,
      level: risk.level,
      factorCount: risk.factors.length,
      topFactors,
    },
    timestamp: risk.timestamp,
    severity: risk.level === 'CRITICAL' ? 'critical' :
              risk.level === 'HIGH' ? 'warning' : 'info',
  };
}
