'use strict';

import * as fs from 'fs';
import {
  RecordedSession, ReplayResult, ScenarioEvent,
  NetworkAuditConfig, NetworkFlow, ProcessEvent,
  FileAccessEvent, GitCommandEvent, Behavior, Evidence,
  Verdict, SessionDna, generateId
} from './types';
import { NetworkAuditPipeline } from './pipeline';

export class ReplayEngine {
  private config: NetworkAuditConfig;
  private pipeline: NetworkAuditPipeline;

  constructor(config?: Partial<NetworkAuditConfig>) {
    this.config = {
      enableProcessMonitor: true,
      enableFileWatcher: true,
      enableGitDetector: true,
      enableDnsObserver: true,
      enableConnectionInspector: true,
      enableHttpInterceptor: false,
      enableWebSocketObserver: false,
      enableTlsInterceptor: false,
      dbPath: '',
      notificationEnabled: false,
      autoStartOnBoot: false,
      trustedHosts: [],
      trustedProcesses: [],
      alertThreshold: 'MEDIUM',
      antiEvasionEnabled: true,
      processChainDetection: true,
      preparationDetection: true,
      canaryConfig: {
        enabled: false,
        decoyFiles: [],
        fakeSecrets: false,
        contaminatedGitHistory: false,
        autoDeploy: false,
      },
      performanceBudget: {
        maxCpuPercent: 50,
        maxMemoryMb: 256,
        maxEventsPerSecond: 10000,
        providerTimeoutMs: 5000,
      },
      ...config,
    };
    this.pipeline = new NetworkAuditPipeline(this.config);
  }

  loadSession(filePath: string): RecordedSession {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const session: RecordedSession = JSON.parse(raw);
    if (session.format !== 'sentinel-session-v1') {
      throw new Error(`Unknown session format: ${session.format}. Expected sentinel-session-v1`);
    }
    return session;
  }

  loadSessionFromJson(json: string): RecordedSession {
    const session: RecordedSession = JSON.parse(json);
    if (session.format !== 'sentinel-session-v1') {
      throw new Error(`Unknown session format: ${session.format}. Expected sentinel-session-v1`);
    }
    return session;
  }

  private coerceTimestamps(obj: any): any {
    if (!obj || typeof obj !== 'object') return obj;
    for (const key of Object.keys(obj)) {
      const val = obj[key];
      if (key === 'timestamp' || key === 'recordedAt' || key === 'replayedAt' || key.endsWith('At')) {
        if (typeof val === 'string') {
          obj[key] = new Date(val);
        }
      } else if (Array.isArray(val)) {
        for (const item of val) {
          this.coerceTimestamps(item);
        }
      } else if (val && typeof val === 'object') {
        this.coerceTimestamps(val);
      }
    }
    return obj;
  }

  replay(session: RecordedSession): ReplayResult {
    const startTime = Date.now();
    const replayId = `replay-${generateId()}`;

    // Deep-clone and coerce string timestamps → Date objects
    const cloned = this.coerceTimestamps(JSON.parse(JSON.stringify(session)));

    const flows: NetworkFlow[] = [];
    const processes: ProcessEvent[] = [];
    const fileAccesses: FileAccessEvent[] = [];
    const gitCommands: GitCommandEvent[] = [];
    const allBehaviors: Behavior[] = [];
    const allEvidence: Evidence[] = [];
    const errors: string[] = [];

    const sessionStart = new Date(cloned.metadata.recordedAt);

    for (const event of cloned.events) {
      try {
        if (event.type === 'flow' && event.data) {
          const flow = event.data as NetworkFlow;
          flow.sessionId = replayId;
          flows.push(flow);
          const result = this.pipeline.processFlow(flow, replayId);
          allBehaviors.push(...result.behaviors);
          allEvidence.push(...result.evidence);
        } else if (event.type === 'process' && event.data) {
          const proc = event.data as ProcessEvent;
          proc.sessionId = replayId;
          processes.push(proc);
          const result = this.pipeline.processProcessEvent(proc, replayId);
          allBehaviors.push(...result.behaviors);
          allEvidence.push(...result.evidence);
        } else if (event.type === 'file_access' && event.data) {
          const fa = event.data as FileAccessEvent;
          fileAccesses.push(fa);
          const result = this.pipeline.processFileAccess(fa, replayId);
          allBehaviors.push(...result.behaviors);
          allEvidence.push(...result.evidence);
        } else if (event.type === 'git_command' && event.data) {
          const gc = event.data as GitCommandEvent;
          gitCommands.push(gc);
          const result = this.pipeline.processGitCommand(gc, replayId);
          allBehaviors.push(...result.behaviors);
          allEvidence.push(...result.evidence);
        }
      } catch (err: any) {
        errors.push(`Error processing ${event.type} event: ${err.message}`);
      }
    }

    // Batch file access aggregation (mass read / embedding)
    if (fileAccesses.length >= 3) {
      try {
        const batchBehavior = this.pipeline.processBatchFileAccess(fileAccesses, replayId);
        if (batchBehavior) {
          allBehaviors.push(batchBehavior);
        }
      } catch (err: any) {
        errors.push(`Error in batch file access analysis: ${err.message}`);
      }
    }

    // Generate verdict
    let verdict: Verdict | null = null;
    try {
      verdict = this.pipeline.generateVerdict(
        replayId, sessionStart, flows, allBehaviors, allEvidence,
        processes, fileAccesses, gitCommands
      );
    } catch (err: any) {
      errors.push(`Error generating verdict: ${err.message}`);
    }

    const durationMs = Date.now() - startTime;

    return {
      sessionId: session.metadata.id,
      sessionName: session.metadata.id,
      verdict,
      riskScore: verdict?.overallRisk.score ?? 0,
      riskLevel: verdict?.overallRisk.level ?? 'LOW',
      confidence: verdict?.sessionDna?.confidence ?? 0,
      behaviorsDetected: allBehaviors.map(b => b.type),
      errors,
      durationMs,
      replayedAt: new Date().toISOString(),
    };
  }

  replayFile(filePath: string): ReplayResult {
    const session = this.loadSession(filePath);
    return this.replay(session);
  }

  getPipeline(): NetworkAuditPipeline {
    return this.pipeline;
  }
}
