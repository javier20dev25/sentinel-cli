'use strict';

import {
  NetworkFlow, ProcessEvent, FileAccessEvent, GitCommandEvent,
  Behavior, BehaviorType, Evidence, RiskAssessment, Verdict, SessionDna,
  NetworkAuditSession, NetworkAuditConfig, CanaryEvent,
  AntiEvasionSignal, AntiEvasionSignalType, EvidenceChain, CoverageInfo, HealthReport,
  generateId
} from './types';
import {
  classifyFlow, classifyProcess, classifyFileAccess,
  classifyGitCommand, computeMassReadBehavior, computeEmbeddingBehavior,
  classifyCanaryEvent, classifyPreparationCommands,
  AI_PROMPT_API_PATHS
} from './behavior-engine';
import { assessRisk } from './risk-engine';
import {
  buildFlowEvidence, buildProcessEvidence, buildFileAccessEvidence,
  buildGitCommandEvidence, buildBehaviorEvidence, buildRiskEvidence,
  buildAntiEvasionEvidence, buildChainEvidence
} from './evidence-builder';
import { buildSessionDna, buildVerdict } from './session-dna';
import { AntiEvasionEngine } from './anti-evasion-engine';
import { EvidenceChainCorrelator } from './evidence-chain';
import { CanarySystem } from './canary-system';
import { HealthMonitor, SENSOR_TRUST_SCORES, DEFAULT_CAPABILITIES } from './providers';

export class NetworkAuditPipeline {
  private config: NetworkAuditConfig;
  private antiEvasionEngine: AntiEvasionEngine;
  private chainCorrelator: EvidenceChainCorrelator;
  private canarySystem: CanarySystem;
  private antiEvasionSignals: AntiEvasionSignal[] = [];
  private evidenceChains: EvidenceChain[] = [];
  healthMonitor: HealthMonitor;

  constructor(config: NetworkAuditConfig) {
    this.config = config;
    this.antiEvasionEngine = new AntiEvasionEngine();
    this.chainCorrelator = new EvidenceChainCorrelator();
    this.canarySystem = new CanarySystem(config.canaryConfig);
    this.healthMonitor = new HealthMonitor();
    this.registerDefaultSensors();
  }

  private registerDefaultSensors(): void {
    const activeProviders = [
      ['ProcessMonitor', 'process'],
      ['FileWatcher', 'filesystem'],
      ['GitDetector', 'git'],
      ['DnsObserver', 'dns'],
      ['ConnectionInspector', 'network'],
      ['HttpInterceptor', 'http'],
      ['TlsInterceptor', 'tls'],
      ['WebSocketObserver', 'websocket'],
    ];

    for (const [name] of activeProviders) {
      const cap = DEFAULT_CAPABILITIES[name];
      if (cap) this.healthMonitor.registerSensor(name, cap);
    }
  }

  computeConfidenceScore(behaviors: Behavior[]): number {
    if (behaviors.length === 0) return 0;
    const avgBehaviorConf = behaviors.reduce((s, b) => s + b.confidence, 0) / behaviors.length;
    const trused = this.healthMonitor.getHealthReport().sensors
      .filter(s => s.ok)
      .map(s => SENSOR_TRUST_SCORES[s.name] ?? 0.8);
    const avgTrust = trused.length > 0
      ? trused.reduce((a, b) => a + b, 0) / trused.length
      : 0;
    return Math.min(100, Math.round(avgBehaviorConf * avgTrust * behaviors.length * 10));
  }

  computeCoverage(): CoverageInfo {
    return this.healthMonitor.computeCoverage();
  }

  getHealthReport(): HealthReport {
    return this.healthMonitor.getHealthReport();
  }

  getSensorCapabilities(): Map<string, import('./types').SensorCapability> {
    return (this.healthMonitor as any)['capabilities'] as Map<string, import('./types').SensorCapability>;
  }

  getAntiEvisionSignals(): AntiEvasionSignal[] {
    return this.antiEvasionSignals;
  }

  getEvidenceChains(): EvidenceChain[] {
    return this.evidenceChains;
  }

  getAntiEvasionEngine(): AntiEvasionEngine {
    return this.antiEvasionEngine;
  }

  getCanarySystem(): CanarySystem {
    return this.canarySystem;
  }

  processFlow(
    flow: NetworkFlow, sessionId: string
  ): { behaviors: Behavior[]; evidence: Evidence[] } {
    const behaviors: Behavior[] = [];
    const evidence: Evidence[] = [];

    evidence.push(buildFlowEvidence(flow, sessionId));

    const flowBehavior = classifyFlow(flow);
    if (flowBehavior) {
      flowBehavior.sessionId = sessionId;
      behaviors.push(flowBehavior);
      evidence.push(buildBehaviorEvidence(flowBehavior, sessionId));
    }

    // Check if outbound flow carries a canary marker
    if (this.config.canaryConfig.enabled && flow.hostname && flow.bodyPreview) {
      const canaryEvent = this.canarySystem.checkFlowForCanary(flow.hostname, flow.bodyPreview, sessionId);
      if (canaryEvent) {
        const canaryBehavior = classifyCanaryEvent(canaryEvent);
        if (canaryBehavior) {
          behaviors.push(canaryBehavior);
          evidence.push(buildBehaviorEvidence(canaryBehavior, sessionId));
        }
      }
    }

    return { behaviors, evidence };
  }

  processProcessEvent(
    proc: ProcessEvent, sessionId: string
  ): { behaviors: Behavior[]; evidence: Evidence[] } {
    const behaviors: Behavior[] = [];
    const evidence: Evidence[] = [];

    evidence.push(buildProcessEvidence(proc, sessionId));

    const procBehavior = classifyProcess(proc);
    if (procBehavior) {
      procBehavior.sessionId = sessionId;
      behaviors.push(procBehavior);
      evidence.push(buildBehaviorEvidence(procBehavior, sessionId));
    }

    return { behaviors, evidence };
  }

  processFileAccess(
    access: FileAccessEvent, sessionId: string
  ): { behaviors: Behavior[]; evidence: Evidence[] } {
    const behaviors: Behavior[] = [];
    const evidence: Evidence[] = [];

    evidence.push(buildFileAccessEvidence(access, sessionId));

    const fileBehavior = classifyFileAccess(access);
    if (fileBehavior) {
      fileBehavior.sessionId = sessionId;
      behaviors.push(fileBehavior);
      evidence.push(buildBehaviorEvidence(fileBehavior, sessionId));
    }

    // Check if this file access hits a deployed canary
    if (this.config.canaryConfig.enabled) {
      const canaryEvent = this.canarySystem.checkFileAccess(access, sessionId);
      if (canaryEvent) {
        const canaryBehavior = classifyCanaryEvent(canaryEvent);
        if (canaryBehavior) {
          behaviors.push(canaryBehavior);
          evidence.push(buildBehaviorEvidence(canaryBehavior, sessionId));
        }
      }
    }

    return { behaviors, evidence };
  }

  processGitCommand(
    cmd: GitCommandEvent, sessionId: string
  ): { behaviors: Behavior[]; evidence: Evidence[] } {
    const behaviors: Behavior[] = [];
    const evidence: Evidence[] = [];

    evidence.push(buildGitCommandEvidence(cmd, sessionId));

    const gitBehavior = classifyGitCommand(cmd);
    if (gitBehavior) {
      gitBehavior.sessionId = sessionId;
      behaviors.push(gitBehavior);
      evidence.push(buildBehaviorEvidence(gitBehavior, sessionId));
    }

    return { behaviors, evidence };
  }

  processBatchFileAccess(
    events: FileAccessEvent[], sessionId: string
  ): Behavior | null {
    const massRead = computeMassReadBehavior(events);
    if (massRead) {
      massRead.sessionId = sessionId;
      return massRead;
    }

    const embedding = computeEmbeddingBehavior(events);
    if (embedding) {
      embedding.sessionId = sessionId;
      return embedding;
    }

    return null;
  }

  generateVerdict(
    sessionId: string, startTime: Date,
    flows: NetworkFlow[], behaviors: Behavior[],
    evidence: Evidence[],
    processes?: ProcessEvent[],
    fileAccesses?: FileAccessEvent[],
    gitCommands?: GitCommandEvent[]
  ): Verdict {
    // 1. Run direct classifiers first (anti-evasion, prep commands, process chain correlator)
    if (this.config.antiEvasionEnabled) {
      const flowSignals = this.antiEvasionEngine.evaluateFlows(flows, sessionId);
      const fileSignals = this.antiEvasionEngine.evaluateFileAccesses(fileAccesses || [], sessionId);
      const procSignals = this.antiEvasionEngine.evaluateProcesses(processes || [], sessionId);
      this.antiEvasionSignals = [...flowSignals, ...fileSignals, ...procSignals];

      for (const s of flowSignals) {
        const b: Behavior = {
          id: s.id, sessionId, type: classifySignalSeverity(s.score, s.type),
          confidence: s.confidence, evidence: s.evidence, artifacts: [],
          timestamp: s.timestamp, source: 'process',
        };
        behaviors.push(b);
        evidence.push(buildAntiEvasionEvidence(s, sessionId));
      }
      for (const s of fileSignals) {
        const b: Behavior = {
          id: s.id, sessionId, type: classifySignalSeverity(s.score, s.type),
          confidence: s.confidence, evidence: s.evidence, artifacts: [],
          timestamp: s.timestamp, source: 'file',
        };
        behaviors.push(b);
        evidence.push(buildAntiEvasionEvidence(s, sessionId));
      }
      for (const s of procSignals) {
        const b: Behavior = {
          id: s.id, sessionId, type: classifySignalSeverity(s.score, s.type),
          confidence: s.confidence, evidence: s.evidence, artifacts: [],
          timestamp: s.timestamp, source: 'process',
        };
        behaviors.push(b);
        evidence.push(buildAntiEvasionEvidence(s, sessionId));
      }
    }

    if (this.config.preparationDetection && processes) {
      for (const p of processes) {
        const prep = classifyPreparationCommands(p);
        if (prep) {
          prep.sessionId = sessionId;
          behaviors.push(prep);
          evidence.push(buildBehaviorEvidence(prep, sessionId));
        }
      }
    }

    if (this.config.processChainDetection && processes && fileAccesses && gitCommands) {
      const chains = this.chainCorrelator.correlate(flows, processes, fileAccesses, gitCommands, behaviors, sessionId);
      this.evidenceChains = chains;

      for (const chain of chains) {
        const chainType: BehaviorType = chain.name === 'ai_embedding_chain'
          ? 'evidence_chain_detected'
          : chain.name === 'pre_operational_snapshot'
            ? 'pre_operational_snapshot_detected'
            : 'evidence_chain_detected';
        const b: Behavior = {
          id: chain.id, sessionId, type: chainType,
          confidence: chain.confidence,
          evidence: [chain.summary, ...chain.steps.map(s => `${s.type}: ${s.description}`)],
          artifacts: [], timestamp: chain.timestamp, source: 'process',
        };
        behaviors.push(b);
        evidence.push(buildChainEvidence(chain, sessionId));
      }
    }

    // 2. Run logical correlation rules (with all base behaviors now populated)
    const hasBundle = behaviors.some(b => b.type === 'git_bundle_created');
    if (hasBundle && !behaviors.some(b => b.type === 'full_repo_snapshot')) {
      behaviors.push({
        id: generateId(),
        sessionId,
        type: 'full_repo_snapshot',
        confidence: 0.9,
        evidence: ['Full repository snapshot inferred from git bundle creation'],
        artifacts: [],
        timestamp: new Date(),
        source: 'git'
      });
    }

    const hasMassRead = behaviors.some(b => b.type === 'mass_file_read');
    const hasGitMeta = behaviors.some(b => b.type === 'git_history_read' || b.type === 'git_objects_read');
    if (hasMassRead && hasGitMeta && !behaviors.some(b => b.type === 'full_repo_snapshot')) {
      behaviors.push({
        id: generateId(),
        sessionId,
        type: 'full_repo_snapshot',
        confidence: 0.9,
        evidence: ['Full repository snapshot inferred from mass file reads combined with Git metadata access'],
        artifacts: [],
        timestamp: new Date(),
        source: 'git'
      });
    }

    const hasCanaryRead = behaviors.some(b => b.type === 'canary_read');
    const hasSecretRead = behaviors.some(b => b.type === 'secrets_scanned' || b.type === 'fake_secret_read');
    // Reduced exfil threshold to 5KB to reliably catch credential/token leaks
    const hasExfil = behaviors.some(b => b.type === 'code_upload' || b.type === 'git_bundle_uploaded') ||
      flows.some(f => f.bytesSent > 5 * 1024 && f.destAddr !== '127.0.0.1');

    const hasBundleCreated = behaviors.some(b => b.type === 'git_bundle_created');
    if (hasBundleCreated && hasExfil && !behaviors.some(b => b.type === 'git_bundle_uploaded')) {
      behaviors.push({
        id: generateId(),
        sessionId,
        type: 'git_bundle_uploaded',
        confidence: 0.95,
        evidence: ['Git bundle upload inferred from bundle creation followed by outbound data transmission'],
        artifacts: [],
        timestamp: new Date(),
        source: 'git'
      });
    }

    if (hasCanaryRead && hasExfil && !behaviors.some(b => b.type === 'canary_exfiltrated')) {
      behaviors.push({
        id: generateId(),
        sessionId,
        type: 'canary_exfiltrated',
        confidence: 0.95,
        evidence: ['Canary exfiltration inferred from canary access followed by outbound data transmission'],
        artifacts: [],
        timestamp: new Date(),
        source: 'file'
      });
    }

    const hasGitObjects = behaviors.some(b => b.type === 'git_objects_read');
    // Git objects pack access + exfiltration (or mass read) triggers full_repo_snapshot
    if (hasGitObjects && hasExfil && !behaviors.some(b => b.type === 'full_repo_snapshot')) {
      behaviors.push({
        id: generateId(),
        sessionId,
        type: 'full_repo_snapshot',
        confidence: 0.9,
        evidence: ['Full repository snapshot inferred from Git objects packfile access followed by network activity'],
        artifacts: [],
        timestamp: new Date(),
        source: 'git'
      });
    }

    const hasGitHistory = behaviors.some(b => b.type === 'git_history_read');
    const isDetailedLog = gitCommands && gitCommands.some(c => {
      const args = c.commandLine.toLowerCase().split(/\s+/);
      return args.includes('-p') || args.includes('--patch') || args.includes('--stat') || args.includes('show');
    });
    if (hasGitHistory && isDetailedLog && this.config.canaryConfig.contaminatedGitHistory && !behaviors.some(b => b.type === 'contaminated_git_read')) {
      behaviors.push({
        id: generateId(),
        sessionId,
        type: 'contaminated_git_read',
        confidence: 0.9,
        evidence: ['Contaminated Git history access detected via Git history enumeration'],
        artifacts: [],
        timestamp: new Date(),
        source: 'git'
      });
    }

    const hasPrep = behaviors.some(b => b.type === 'preparation_detected');
    if (hasPrep) {
      flows.forEach(f => {
        const isLocal = f.destAddr === '127.0.0.1' || f.destAddr === '::1' || f.destAddr.startsWith('10.') || f.destAddr.startsWith('192.168.') || f.destAddr.startsWith('172.');
        if (!isLocal && !behaviors.some(b => b.type === 'suspicious_connection')) {
          behaviors.push({
            id: generateId(),
            sessionId,
            type: 'suspicious_connection',
            confidence: 0.8,
            evidence: [`Outbound connection to ${f.hostname ?? f.destAddr} following system preparation command`],
            artifacts: [],
            timestamp: new Date(),
            source: 'connection'
          });
        }
      });
    }

    flows.forEach(f => {
      const isAiPrompt = f.path != null && AI_PROMPT_API_PATHS.some(p => f.path!.includes(p));
      if (isAiPrompt && !behaviors.some(b => b.type === 'ai_prompt_sent')) {
        behaviors.push({
          id: generateId(),
          sessionId,
          type: 'ai_prompt_sent',
          confidence: 0.9,
          evidence: [`AI prompt sent via endpoint: ${f.method ?? 'POST'} ${f.path}`],
          artifacts: [],
          timestamp: new Date(),
          source: 'connection'
        });
      }
    });

    if (hasSecretRead && hasExfil && !behaviors.some(b => b.type === 'secrets_exfiltrated')) {
      behaviors.push({
        id: generateId(),
        sessionId,
        type: 'secrets_exfiltrated',
        confidence: 0.95,
        evidence: ['Secrets exfiltration inferred from secret file access followed by outbound data transmission'],
        artifacts: [],
        timestamp: new Date(),
        source: 'file'
      });
    }

    const risk = assessRisk(behaviors);
    const riskEvidence = buildRiskEvidence(risk, sessionId);
    const allEvidence = [...evidence, riskEvidence];

    const coverage = this.computeCoverage();
    const health = this.getHealthReport();

    const dna = buildSessionDna(
      sessionId, startTime, flows, behaviors, allEvidence, risk,
      this.antiEvasionSignals, this.evidenceChains, coverage, health
    );

    const confidenceScore = this.computeConfidenceScore(behaviors);
    return buildVerdict(sessionId, risk, behaviors, allEvidence, dna, confidenceScore, coverage, health);
  }

  reset(): void {
    this.antiEvasionSignals = [];
    this.evidenceChains = [];
    this.chainCorrelator.reset();
  }
}

// Fix F: map each AntiEvasionSignalType to its proper BehaviorType.
// Previously all signals collapsed to 'anti_evasion_detected', losing
// the distinction between process chains and monitor awareness.
function classifySignalSeverity(score: number, signalType?: AntiEvasionSignalType): BehaviorType {
  if (signalType === 'process_chain') return 'process_chain_detected';
  if (signalType === 'monitor_awareness') return 'monitor_awareness_detected';

  const EVASION_TYPES: AntiEvasionSignalType[] = [
    'artificial_rhythm', 'fragmented_traffic', 'protocol_hopping',
    'custom_compression', 'memory_only_ops', 'distributed_chain', 'no_temp_files'
  ];
  if (signalType && EVASION_TYPES.includes(signalType)) {
    return 'anti_evasion_detected';
  }

  if (score >= 30) return 'anti_evasion_detected';
  return 'process_suspicious';
}
