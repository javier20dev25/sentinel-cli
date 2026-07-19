'use strict';

import * as readline from 'readline';
import { AuditDatabase } from './database';
import { NotificationProvider } from './notification-provider';
import { ProcessMonitor } from './process-monitor';
import { FileWatcher } from './file-watcher';
import { GitDetector } from './git-detector';
import { DnsObserver } from './dns-observer';
import { ConnectionInspector } from './connection-inspector';
import { HttpInterceptor } from './http-interceptor';
import { WebSocketObserver } from './websocket-observer';
import { TlsInterceptor } from './tls-interceptor';
import { NetworkAuditPipeline } from '../../core/network/pipeline';
import {
  NetworkAuditSession, NetworkAuditConfig,
  NetworkFlow, Behavior, Evidence, FileAccessEvent,
  Verdict, SessionDna, generateId, CanaryConfig, CanaryEvent,
  BlindSpotEntry
} from '../../core/network/types';
import { CanarySystem } from '../../core/network/canary-system';
import { classifyCanaryEvent } from '../../core/network/behavior-engine';
import { renderSessionStatus, renderFlow, renderVerdict, renderDnaSummary, renderSessionHistory, renderBlindSpotEntry, renderBlindSpotLog, renderCampaignReport } from './render-network';
import { CampaignRunner } from '../../core/network/campaign-runner';
import { SCENARIOS } from '../../core/network/scenarios';
import { ReplayEngine } from '../../core/network/replay-engine';
import { runReplayCampaign, renderReplayCampaignSummary } from '../../core/network/replay-campaign';
import { SessionRecorder } from './session-recorder';
import { renderBenchmarkHistory } from '../../core/network/benchmark-history';
import { computeCorpusCoverage, renderCorpusCoverage } from './corpus-coverage';
import { exportSessionJson, exportMarkdown } from './export-network';

export class NetworkAuditor {
  private db: AuditDatabase;
  private notification: NotificationProvider;
  private pipeline: NetworkAuditPipeline;
  private config: NetworkAuditConfig;

  private processMonitor?: ProcessMonitor;
  private fileWatcher?: FileWatcher;
  private gitDetector?: GitDetector;
  private dnsObserver?: DnsObserver;
  private connectionInspector?: ConnectionInspector;
  private httpInterceptor?: HttpInterceptor;
  private wsObserver?: WebSocketObserver;
  private tlsInterceptor?: TlsInterceptor;

  private session: NetworkAuditSession | null = null;
  private running = false;
  private fileAccessBuffer: FileAccessEvent[] = [];
  private processBuffer: import('../../core/network/types').ProcessEvent[] = [];
  private gitBuffer: import('../../core/network/types').GitCommandEvent[] = [];
  private dashboardInterval: ReturnType<typeof setInterval> | null = null;
  private canarySystem: CanarySystem | null = null;

  constructor(db?: AuditDatabase) {
    this.db = db || new AuditDatabase();
    this.notification = new NotificationProvider(true);
    this.config = this.defaultConfig();
    this.pipeline = new NetworkAuditPipeline(this.config);
  }

  private defaultConfig(): NetworkAuditConfig {
    return {
      enableProcessMonitor: true,
      enableFileWatcher: true,
      enableGitDetector: true,
      enableDnsObserver: true,
      enableConnectionInspector: true,
      enableHttpInterceptor: false,
      enableWebSocketObserver: false,
      enableTlsInterceptor: false,
      dbPath: '',
      notificationEnabled: true,
      autoStartOnBoot: false,
      trustedHosts: [],
      trustedProcesses: [],
      alertThreshold: 'MEDIUM',
      antiEvasionEnabled: true,
      processChainDetection: true,
      preparationDetection: true,
      canaryConfig: {
        enabled: true,
        decoyFiles: [],
        fakeSecrets: true,
        contaminatedGitHistory: true,
        autoDeploy: false,
      },
      performanceBudget: {
        maxCpuPercent: 50,
        maxMemoryMb: 256,
        maxEventsPerSecond: 10000,
        providerTimeoutMs: 5000,
      },
    };
  }

  async start(): Promise<void> {
    if (this.running) {
      console.log('Network Auditor is already running.');
      return;
    }

    this.session = {
      id: generateId(),
      startTime: new Date(),
      status: 'running',
      config: this.config,
      flows: [],
      behaviors: [],
      evidence: [],
    };

    this.db.createSession(this.session.id, this.config as unknown as Record<string, unknown>);
    this.running = true;

    this.canarySystem = new CanarySystem(this.config.canaryConfig);
    this.canarySystem.deployCanaries(process.cwd());
    if (this.canarySystem.getDeployedCount() > 0) {
      console.log(`  ${this.canarySystem.getDeployedCount()} canary files deployed`);
    }

    this.pipeline.getAntiEvasionEngine().start(this.session.startTime);

    if (this.config.enableProcessMonitor) {
      this.processMonitor = new ProcessMonitor(2000);
      this.processMonitor.start((event) => {
        if (!this.session) return;
        this.processBuffer.push(event);
        const result = this.pipeline.processProcessEvent(event, this.session!.id);
        for (const b of result.behaviors) {
          this.db.insertBehavior({
            id: b.id, session_id: b.sessionId, timestamp: b.timestamp.toISOString(),
            type: b.type, confidence: b.confidence, source: b.source,
            evidence_json: JSON.stringify(b.evidence),
            artifacts_json: JSON.stringify(b.artifacts),
          });
        }
        for (const e of result.evidence) {
          this.db.insertEvidence({
            id: e.id, session_id: e.sessionId, timestamp: e.timestamp.toISOString(),
            type: e.type, title: e.title, description: e.description,
            data_json: JSON.stringify(e.data), severity: e.severity,
          });
          if (e.severity === 'critical' || (e.severity === 'warning' && this.config.alertThreshold !== 'HIGH')) {
            this.notification.sendAlert(
              e.title, e.description, e.severity === 'critical' ? 'CRITICAL' : 'HIGH'
            );
          }
        }
        this.db.insertProcess({
          session_id: event.sessionId || this.session!.id,
          timestamp: event.timestamp.toISOString(),
          pid: event.pid, name: event.name,
          command_line: event.commandLine.substring(0, 500),
          parent_pid: event.parentPid,
          parent_name: event.parentName,
          username: event.username,
          risk_indicators_json: JSON.stringify(event.riskIndicators),
        });
      });
    }

    if (this.config.enableFileWatcher) {
      this.fileWatcher = new FileWatcher(3000);
      this.fileWatcher.addWatchPath(process.cwd());
      this.fileWatcher.start((event) => {
        if (!this.session) return;
        this.fileAccessBuffer.push(event);

        if (this.canarySystem) {
          const canaryEvent = this.canarySystem.checkFileAccess(event, this.session!.id);
          if (canaryEvent) {
            const canaryBehavior = classifyCanaryEvent({
              type: canaryEvent.type,
              canaryName: canaryEvent.canaryName,
              confidence: canaryEvent.confidence,
              timestamp: canaryEvent.timestamp,
              sessionId: canaryEvent.sessionId,
              processName: canaryEvent.processName,
            });
            if (canaryBehavior) {
              canaryBehavior.sessionId = this.session!.id;
              this.session.behaviors.push(canaryBehavior);
              this.notification.sendAlert(
                `Canary triggered: ${canaryEvent.canaryName}`,
                canaryEvent.detail,
                'CRITICAL'
              );
            }
            this.db.insertCanaryEvent({
              id: canaryEvent.id, session_id: canaryEvent.sessionId,
              type: canaryEvent.type, canary_name: canaryEvent.canaryName,
              confidence: canaryEvent.confidence,
              process_name: canaryEvent.processName, pid: canaryEvent.pid,
              detail: canaryEvent.detail,
              timestamp: canaryEvent.timestamp.toISOString(),
            } as Record<string, unknown>);
          }
        }

        const result = this.pipeline.processFileAccess(event, this.session!.id);
        this.session.behaviors.push(...result.behaviors);
        this.session.evidence.push(...result.evidence);
        this.db.insertFileAccess({
          session_id: this.session!.id,
          timestamp: event.timestamp.toISOString(),
          file_path: event.filePath, process_name: event.processName,
          pid: event.pid, operation: event.operation,
          bytes_read: event.bytesRead,
        });
      });
      setInterval(() => {
        if (this.fileAccessBuffer.length > 0 && this.session) {
          const batch = this.fileAccessBuffer.splice(0);
          const massRead = this.pipeline.processBatchFileAccess(batch, this.session!.id);
          if (massRead) {
            this.session.behaviors.push(massRead);
            this.notification.sendAlert(
              massRead.type.replace(/_/g, ' '),
              massRead.evidence.join('; '),
              'MEDIUM'
            );
          }
        }
      }, 5000);
    }

    if (this.config.enableGitDetector) {
      this.gitDetector = new GitDetector(3000);
      this.gitDetector.start((event) => {
        if (!this.session) return;
        this.gitBuffer.push(event);
        const result = this.pipeline.processGitCommand(event, this.session!.id);
        this.db.insertGitCommand({
          session_id: this.session!.id,
          timestamp: event.timestamp.toISOString(),
          pid: event.pid, process_name: event.processName,
          command_line: event.commandLine.substring(0, 500),
          action: event.action, repository: event.repository,
        });
        for (const b of result.behaviors) {
          this.notification.sendAlert(
            `Git command: ${event.action}`,
            event.commandLine.substring(0, 200),
            'HIGH'
          );
        }
      });
    }

    if (this.config.enableDnsObserver) {
      this.dnsObserver = new DnsObserver();
      this.dnsObserver.start(this.session.id, (flow) => {
        if (!this.session) return;
        this.handleFlow(flow);
      });
    }

    if (this.config.enableConnectionInspector) {
      this.connectionInspector = new ConnectionInspector();
      this.connectionInspector.start(this.session.id, (flow) => {
        if (!this.session) return;
        this.handleFlow(flow);
      });
    }

    if (this.config.enableHttpInterceptor) {
      this.httpInterceptor = new HttpInterceptor(8089, false);
      this.httpInterceptor.start(this.session.id, (flow) => {
        if (!this.session) return;
        this.handleFlow(flow);
      });
      console.log(`  HTTP proxy running on ${this.httpInterceptor.getProxyUrl()}`);
    }

    if (this.config.enableWebSocketObserver) {
      this.wsObserver = new WebSocketObserver();
      this.wsObserver.start(this.session.id, (flow) => {
        if (!this.session) return;
        this.handleFlow(flow);
      });
    }

    if (this.config.enableTlsInterceptor) {
      this.tlsInterceptor = new TlsInterceptor(9090);
      this.tlsInterceptor.start(this.session.id, (flow) => {
        if (!this.session) return;
        this.handleFlow(flow);
      });
      console.log(`  TLS interceptor on port 9090 (SNI extraction only)`);
    }

    this.startDashboard();
    console.log('\nNetwork Auditor started. Monitoring activity...');
  }

  private handleFlow(flow: NetworkFlow): void {
    if (!this.session) return;
    flow.sessionId = this.session.id;
    this.session.flows.push(flow);

    const result = this.pipeline.processFlow(flow, this.session.id);
    this.session.behaviors.push(...result.behaviors);
    this.session.evidence.push(...result.evidence);

    const flowForDb: Record<string, unknown> = {
      id: flow.id, session_id: flow.sessionId, timestamp: flow.timestamp.toISOString(),
      protocol: flow.protocol, source_addr: flow.sourceAddr,
      source_port: flow.sourcePort, dest_addr: flow.destAddr,
      dest_port: flow.destPort, hostname: flow.hostname,
      sni: flow.sni, tls_version: flow.tlsVersion,
      bytes_sent: flow.bytesSent, bytes_received: flow.bytesReceived,
      duration_ms: flow.durationMs, method: flow.method,
      path: flow.path, content_type: flow.contentType,
      status_code: flow.statusCode,
      headers_json: flow.headers ? JSON.stringify(flow.headers) : undefined,
      body_preview: flow.bodyPreview,
      dns_query: flow.dnsQuery,
      dns_response_json: flow.dnsResponse ? JSON.stringify(flow.dnsResponse) : undefined,
    };
    this.db.insertFlow(flowForDb);

    for (const b of result.behaviors) {
      this.db.insertBehavior({
        id: b.id, session_id: b.sessionId, timestamp: b.timestamp.toISOString(),
        type: b.type, confidence: b.confidence, source: b.source,
        evidence_json: JSON.stringify(b.evidence),
        artifacts_json: JSON.stringify(b.artifacts),
      });
    }
    for (const e of result.evidence) {
      this.db.insertEvidence({
        id: e.id, session_id: e.sessionId, timestamp: e.timestamp.toISOString(),
        type: e.type, title: e.title, description: e.description,
        data_json: JSON.stringify(e.data), severity: e.severity,
        flow_id: e.flowId,
      });
      if (e.severity === 'warning' || e.severity === 'critical') {
        this.db.insertAlert({
          session_id: e.sessionId, timestamp: e.timestamp.toISOString(),
          severity: e.severity, title: e.title, description: e.description,
          evidence_json: JSON.stringify(e.data),
        });
        this.notification.sendAlert(e.title, e.description,
          e.severity === 'critical' ? 'CRITICAL' : 'HIGH');
      }
    }
  }

  private startDashboard(): void {
    this.dashboardInterval = setInterval(() => {
      if (!this.session || !this.running) return;
      console.clear();
      console.log(renderSessionStatus(this.session));
      const recentFlows = this.session.flows.slice(-5);
      for (const f of recentFlows) {
        console.log(renderFlow(f));
      }
      if (this.session.behaviors.length > 0) {
        console.log('\nRecent behaviors:');
        for (const b of this.session.behaviors.slice(-3)) {
          console.log(`  [${(b.confidence * 100).toFixed(0)}%] ${b.type.replace(/_/g, ' ')}`);
        }
      }
    }, 3000);
  }

  stop(): Verdict | null {
    if (!this.running || !this.session) {
      console.log('Network Auditor is not running.');
      return null;
    }

    this.running = false;

    if (this.dashboardInterval) {
      clearInterval(this.dashboardInterval);
      this.dashboardInterval = null;
    }

    this.processMonitor?.stop();
    this.fileWatcher?.stop();
    this.gitDetector?.stop();
    this.dnsObserver?.stop();
    this.connectionInspector?.stop();
    this.httpInterceptor?.stop();
    this.wsObserver?.stop();
    this.tlsInterceptor?.stop();

    this.session.endTime = new Date();
    this.session.status = 'stopped';
    this.db.endSession(this.session.id);

    const verdict = this.pipeline.generateVerdict(
      this.session.id, this.session.startTime,
      this.session.flows, this.session.behaviors, this.session.evidence,
      this.processBuffer, this.fileAccessBuffer, this.gitBuffer
    );
    this.session.verdict = verdict;

    this.db.saveVerdict({
      session_id: verdict.sessionId,
      risk_score: verdict.overallRisk.score,
      risk_level: verdict.overallRisk.level,
      verdict_summary: verdict.sessionDna.verdictSummary,
      dna_json: JSON.stringify(verdict.sessionDna),
      generated_at: verdict.timestamp.toISOString(),
    });

    const signals = this.pipeline.getAntiEvisionSignals();
    for (const s of signals) {
      this.db.insertAntiEvasionSignal({
        id: s.id, session_id: s.sessionId,
        type: s.type, score: s.score, confidence: s.confidence,
        evidence_json: JSON.stringify(s.evidence),
        details_json: JSON.stringify(s.details),
        timestamp: s.timestamp.toISOString(),
      } as Record<string, unknown>);
    }

    const chains = this.pipeline.getEvidenceChains();
    for (const c of chains) {
      this.db.insertEvidenceChain({
        id: c.id, session_id: c.sessionId,
        name: c.name, confidence: c.confidence,
        steps_json: JSON.stringify(c.steps),
        summary: c.summary,
      } as Record<string, unknown>);
    }

    if (this.canarySystem) {
      for (const ce of this.canarySystem.getCanaryEvents()) {
        this.db.insertCanaryEvent({
          id: ce.id, session_id: ce.sessionId,
          type: ce.type, canary_name: ce.canaryName,
          confidence: ce.confidence, process_name: ce.processName,
          pid: ce.pid, detail: ce.detail,
          timestamp: ce.timestamp.toISOString(),
        } as Record<string, unknown>);
      }
      this.canarySystem.cleanup();
    }

    const sessionObj = this.session;
    console.clear();
    console.log(renderVerdict(verdict));
    console.log(renderDnaSummary(verdict.sessionDna));

    if (verdict.sessionDna.antiEvasionScore > 0) {
      console.log(`\nAnti-Evasion Score: ${verdict.sessionDna.antiEvasionScore}/100`);
      if (verdict.sessionDna.antiEvasionSignals.length > 0) {
        console.log(`Signals: ${verdict.sessionDna.antiEvasionSignals.join(', ')}`);
      }
    }
    if (verdict.sessionDna.hasCanaryTrigger) {
      console.log('\n⚠️ CANARY TRIGGERED — decoy files were accessed');
    }
    if (verdict.sessionDna.evidenceChains.length > 0) {
      console.log(`\nEvidence Chains: ${verdict.sessionDna.evidenceChains.join(', ')}`);
    }

    this.notification.send(
      'Sentinel Network Audit Complete',
      `Risk: ${verdict.overallRisk.level} (${verdict.overallRisk.score}/100)` +
      (verdict.sessionDna.antiEvasionScore > 0 ? ` | Anti-Evasion: ${verdict.sessionDna.antiEvasionScore}/100` : ''),
      verdict.overallRisk.level === 'CRITICAL' ? 'critical' : 'info'
    );

    this.pipeline.reset();

    return verdict;
  }

  getStatus(): { running: boolean; session: NetworkAuditSession | null } {
    return { running: this.running, session: this.session };
  }

  getVerdict(): Verdict | null {
    return this.session?.verdict || null;
  }

  getSessionHistory(limit = 10): Array<Record<string, unknown>> {
    return this.db.getSessions(limit);
  }

  showHistory(): void {
    const sessions = this.db.getSessions(10);
    console.log(renderSessionHistory(sessions as Array<{
      id: string; start_time: string; end_time: string;
      status: string; risk_level?: string; risk_score?: number;
    }>));
  }

  showSessionDetail(sessionId: string): void {
    const behaviors = this.db.getSessionBehaviors(sessionId);
    const evidence = this.db.getSessionEvidence(sessionId);
    const flows = this.db.getSessionFlows(sessionId);
    const verdict = this.db.getSessionVerdict(sessionId);

    console.log(`\nSession: ${sessionId}`);
    console.log(`Flows: ${flows.length}`);
    console.log(`Behaviors: ${behaviors.length}`);
    console.log(`Evidence: ${evidence.length}`);

    if (verdict) {
      console.log(`Risk: ${verdict.risk_level} (${verdict.risk_score}/100)`);
      console.log(`Verdict: ${verdict.verdict_summary}`);
    }

    if (behaviors.length > 0) {
      console.log('\nBehaviors:');
      for (const b of behaviors) {
        console.log(`  [${(b.confidence as number * 100).toFixed(0)}%] ${(b.type as string).replace(/_/g, ' ')}`);
      }
    }
  }

  exportSession(sessionId: string, format: 'json' | 'markdown'): string {
    const behaviors = this.db.getSessionBehaviors(sessionId);
    const evidence = this.db.getSessionEvidence(sessionId);
    const flows = this.db.getSessionFlows(sessionId);
    const verdictRow = this.db.getSessionVerdict(sessionId);

    if (verdictRow && typeof verdictRow.dna_json === 'string') {
      try {
        const dna = JSON.parse(verdictRow.dna_json) as SessionDna;
      } catch {
      }
    }

    const sessions = this.db.getSessions(1);
    const sessionRow = sessions.find((s: Record<string, unknown>) => s.id === sessionId);
    if (!sessionRow) return JSON.stringify({ error: 'Session not found' });

    const session: NetworkAuditSession = {
      id: sessionRow.id as string,
      startTime: new Date(sessionRow.start_time as string),
      endTime: sessionRow.end_time ? new Date(sessionRow.end_time as string) : undefined,
      status: sessionRow.status as 'running' | 'stopped',
      config: {} as NetworkAuditConfig,
      flows: [],
      behaviors: behaviors.map((b: Record<string, unknown>) => ({
        id: b.id as string,
        sessionId: b.session_id as string,
        type: b.type as never,
        confidence: b.confidence as number,
        evidence: typeof b.evidence_json === 'string' ? JSON.parse(b.evidence_json) : [],
        artifacts: typeof b.artifacts_json === 'string' ? JSON.parse(b.artifacts_json) : [],
        timestamp: new Date(b.timestamp as string),
        source: b.source as never,
      })),
      evidence: evidence.map((e: Record<string, unknown>) => ({
        id: e.id as string,
        sessionId: e.session_id as string,
        type: e.type as never,
        title: e.title as string,
        description: e.description as string,
        data: typeof e.data_json === 'string' ? JSON.parse(e.data_json) : {},
        timestamp: new Date(e.timestamp as string),
        severity: e.severity as 'info' | 'warning' | 'critical',
      })),
    };

    if (format === 'markdown') {
      return exportMarkdown(session);
    }
    return exportSessionJson(session);
  }

  addTrustedAgent(name: string): void {
    this.db.addTrustedAgent(name);
    console.log(`Trusted agent '${name}' added.`);
  }

  removeTrustedAgent(name: string): void {
    this.db.removeTrustedAgent(name);
    console.log(`Trusted agent '${name}' removed.`);
  }

  listTrustedAgents(): void {
    const agents = this.db.getTrustedAgents();
    console.log('\nTrusted Agents:');
    console.log('─'.repeat(40));
    for (const a of agents) {
      console.log(`  ${a.name}${a.executable ? ' (' + a.executable + ')' : ''}`);
    }
    if (agents.length === 0) console.log('  (none)');
  }

  blindspots(
    action: 'list' | 'add' | 'show' | 'update' | 'delete' | 'stats',
    ...args: string[]
  ): void {
    switch (action) {
      case 'list': {
        const status = args[0] || undefined;
        const sensor = args[1] || undefined;
        const raw = this.db.getBlindSpots(status, undefined, sensor) as Array<Record<string, unknown>>;
        const entries = raw.map(r => rowToBlindSpot(r));
        const stats = this.db.getBlindSpotStats() as any;
        console.log(renderBlindSpotLog(entries, {
          total: stats.total as number,
          open: stats.open as number,
          resolved: stats.resolved as number,
          bySeverity: stats.bySeverity as Array<{ severity: string; count: number }>,
          bySensor: stats.bySensor as Array<{ sensor_failed: string; count: number }>,
        }));
        break;
      }
      case 'add': {
        const rl = require('readline').createInterface({
          input: process.stdin, output: process.stdout,
        });
        const ask = (q: string): Promise<string> => new Promise(r => rl.question(q, r));
        (async () => {
          const title = await ask('Title: ');
          const sensor = await ask('Sensor that failed: ');
          const how = await ask('How it happened: ');
          const expected = await ask('What was expected: ');
          const actual = await ask('What was actually observed: ');
          const impact = await ask('Impact: ');
          const severity = await ask('Severity (low/medium/high/critical): ') || 'medium';
          const id = generateId();
          const now = new Date().toISOString();
          this.db.insertBlindSpot({
            id, title: title || 'Untitled',
            description: '', how_it_happened: how,
            sensor_failed: sensor, expected_behavior: expected,
            actual_observation: actual, impact: impact || 'Unknown',
            severity: severity, status: 'open',
            session_id: this.session?.id || null,
            created_at: now, updated_at: now,
            resolved_at: null, resolution: null,
          });
          console.log(`\nBlind spot logged: ${id}`);
          rl.close();
        })();
        break;
      }
      case 'show': {
        const id = args[0];
        if (!id) { console.log('Usage: sentinel network blindspots show <id>'); return; }
        const raw = this.db.getBlindSpots(undefined, undefined, undefined, 1000) as Array<Record<string, unknown>>;
        const found = raw.find(r => r.id === id);
        if (!found) { console.log(`Blind spot not found: ${id}`); return; }
        console.log(renderBlindSpotEntry(rowToBlindSpot(found)));
        break;
      }
      case 'update': {
        const id = args[0];
        const status = args[1];
        const resolution = args.slice(2).join(' ');
        if (!id || !status) { console.log('Usage: sentinel network blindspots update <id> <status> [resolution]'); return; }
        this.db.updateBlindSpotStatus(id, status, resolution || undefined);
        console.log(`Blind spot ${id} → ${status}`);
        break;
      }
      case 'delete': {
        const id = args[0];
        if (!id) { console.log('Usage: sentinel network blindspots delete <id>'); return; }
        this.db.deleteBlindSpot(id);
        console.log(`Blind spot ${id} deleted.`);
        break;
      }
      case 'stats': {
        const stats = this.db.getBlindSpotStats() as any;
        console.log('\nBlind Spot Statistics:');
        console.log('─'.repeat(50));
        console.log(`  Total:     ${stats.total}`);
        console.log(`  Open:      ${stats.open}`);
        console.log(`  Resolved:  ${stats.resolved}`);
        if (stats.bySeverity?.length > 0) {
          console.log('\n  By Severity:');
          for (const s of stats.bySeverity as Array<{ severity: string; count: number }>) {
            console.log(`    ${s.severity}: ${s.count}`);
          }
        }
        if (stats.bySensor?.length > 0) {
          console.log('\n  By Sensor:');
          for (const s of stats.bySensor as Array<{ sensor_failed: string; count: number }>) {
            console.log(`    ${s.sensor_failed}: ${s.count}`);
          }
        }
        break;
      }
      default:
        console.log('Usage: sentinel network blindspots <list|add|show|update|delete|stats>');
    }
  }

  doctor(showMetrics = false, showCoverage = false, showDrift = false): void {
    const health = this.pipeline.getHealthReport();
    const coverage = this.pipeline.computeCoverage();

    console.log('\n═══ Network Auditor Health Report ═══');
    console.log(`Status: ${health.status.toUpperCase()}`);
    console.log(`Timestamp: ${health.timestamp.toISOString()}`);
    console.log('');

    console.log('Sensors:');
    for (const s of health.sensors) {
      const icon = s.ok ? '✓' : '✗';
      const cap = this.pipeline.getSensorCapabilities().get(s.name);
      console.log(`  ${icon} ${s.name} [${s.ok ? 'OK' : 'FAIL'}] (${s.latencyMs}ms)`);
      if (showCoverage && cap) {
        console.log(`      Detects: ${cap.detects.join(', ')}`);
        console.log(`      Blind:   ${cap.cannotDetect.join(', ')}`);
        console.log(`      Confidence: ${(cap.confidence * 100).toFixed(0)}%`);
      }
      if (s.error) console.log(`      Error: ${s.error}`);
    }

    console.log('');
    console.log(`Coverage Score: ${(coverage.score * 100).toFixed(0)}%`);
    console.log(`Sensors Active: ${coverage.totalActive}/${coverage.totalConfigured}`);

    if (showCoverage && coverage.blindSpots.length > 0) {
      console.log(`\nBlind Spots: ${coverage.blindSpots.join(', ')}`);
      console.log('\nPer-Sensor Coverage:');
      for (const s of coverage.sensors) {
        const bar = '█'.repeat(Math.round(s.coverage / 5)) + '░'.repeat(Math.max(0, 20 - Math.round(s.coverage / 5)));
        console.log(`  ${s.name.padEnd(20)} ${bar} ${s.coverage.toFixed(1)}%`);
      }
    }

    if (showMetrics) {
      const m = health.metrics;
      console.log('\nRuntime Metrics:');
      console.log(`  Flows Received:     ${m.flowsReceived}`);
      console.log(`  Flows Discarded:    ${m.flowsDiscarded}`);
      console.log(`  Avg Process Time:   ${m.avgProcessTimeMs}ms`);
      console.log(`  Events/sec:         ${m.eventsPerSecond}`);
      console.log(`  Backpressure:       ${m.backpressure ? 'YES' : 'NO'}`);
      console.log(`  Buffer Usage:       ${m.bufferUsage}`);
      console.log(`  Peak Memory:        ${m.peakMemoryMb}MB`);
      console.log(`  Queue Depth:        ${m.queueDepth}`);
      console.log(`  Uptime:             ${(m.uptimeMs / 1000).toFixed(1)}s`);
    }

    if (showDrift) {
      console.log('\nSensor Confidence Drift:');
      const beforeScore = coverage.score;
      const afterCoverage = this.pipeline.computeCoverage();
      const afterScore = afterCoverage.score;
      const delta = ((afterScore - beforeScore) * 100).toFixed(1);
      console.log(`  Before self-test: ${(beforeScore * 100).toFixed(0)}%`);
      console.log(`  After self-test:  ${(afterScore * 100).toFixed(0)}%`);
      console.log(`  Delta:            ${delta}%`);
      console.log(`  Interpretation:   ${Math.abs(Number(delta)) < 5 ? 'Stable' : 'Drift detected'}`);
    }
  }

  campaign(
    action: 'list' | 'run' | 'show' | 'delete',
    ...args: string[]
  ): void {
    switch (action) {
      case 'list': {
        const summaries = this.db.getCampaignSummaries();
        if (summaries.length === 0) {
          console.log('\nNo campaigns run yet. Use: sentinel network campaign run');
          return;
        }
        console.log('\nCampaigns:');
        console.log('─'.repeat(80));
        for (const s of summaries) {
          const total = s.total as number;
          const rate = total > 0 ? (((s.passed as number) / total) * 100).toFixed(0) : '0';
          console.log(`  ${(s.campaign_id as string).substring(0, 20).padEnd(22)} passed:${s.passed}/${s.total} (${rate}%) avg_risk:${s.avg_risk} coverage:${s.avg_coverage}% last:${s.last_run}`);
        }
        break;
      }
      case 'run': {
        const runner = new CampaignRunner();
        const tagFilter = args[0] || undefined;
        const scenarios = tagFilter
          ? SCENARIOS.filter(s => s.tags.includes(tagFilter))
          : SCENARIOS;
        if (scenarios.length === 0) {
          console.log(`No scenarios found with tag: ${tagFilter}`);
          return;
        }
        console.log(`\nRunning ${scenarios.length} scenarios${tagFilter ? ` (tag: ${tagFilter})` : ''}...`);
        const report = runner.runCampaign(scenarios, {
          id: `campaign-${Date.now().toString(36)}`,
          name: tagFilter ? `tag:${tagFilter}` : 'full',
          description: tagFilter ? `Scenarios tagged: ${tagFilter}` : 'All scenarios',
          scenarioIds: scenarios.map(s => s.id),
          createdAt: new Date(),
        });
        console.log(renderCampaignReport(report));
        for (const r of report.results) {
          this.db.insertCampaignResult({
            campaign_id: report.campaignId,
            scenario_id: r.scenarioId,
            scenario_name: r.scenarioName,
            passed: r.passed ? 1 : 0,
            risk_level: r.riskLevel,
            risk_score: r.riskScore,
            confidence_score: r.confidenceScore,
            coverage_score: r.coverageScore,
            behaviors_json: JSON.stringify(r.behaviorsDetected),
            expected_json: JSON.stringify(r.expectedBehaviors),
            missing_json: JSON.stringify(r.missingBehaviors),
            unexpected_json: JSON.stringify(r.unexpectedBehaviors),
            errors_json: JSON.stringify(r.errors),
            details_json: JSON.stringify(r.details),
            duration_ms: r.durationMs,
            ran_at: r.timestamp.toISOString(),
          });
        }
        break;
      }
      case 'show': {
        const id = args[0];
        if (!id) { console.log('Usage: sentinel network campaign show <campaign_id>'); return; }
        const rows = this.db.getCampaignResults(id);
        if (rows.length === 0) { console.log(`Campaign not found: ${id}`); return; }
        const results = rows.map(r => ({
          scenarioId: r.scenario_id as string,
          scenarioName: r.scenario_name as string,
          passed: (r.passed as number) === 1,
          riskLevel: r.risk_level as string,
          riskScore: r.risk_score as number,
          confidenceScore: r.confidence_score as number,
          coverageScore: r.coverage_score as number,
          behaviorsDetected: JSON.parse((r.behaviors_json as string) || '[]'),
          expectedBehaviors: JSON.parse((r.expected_json as string) || '[]'),
          missingBehaviors: JSON.parse((r.missing_json as string) || '[]'),
          unexpectedBehaviors: JSON.parse((r.unexpected_json as string) || '[]'),
          errors: JSON.parse((r.errors_json as string) || '[]'),
          durationMs: r.duration_ms as number,
          timestamp: new Date(r.ran_at as string),
          details: JSON.parse((r.details_json as string) || '{}'),
        }));
        const total = results.length;
        const passed = results.filter(r => r.passed).length;
        const report: import('../../core/network/types').CampaignReport = {
          campaignId: id,
          name: id,
          totalScenarios: total,
          passed,
          failed: total - passed,
          passRate: total > 0 ? Math.round((passed / total) * 1000) / 10 : 0,
          avgRiskScore: results.length > 0 ? Math.round(results.reduce((s, r) => s + r.riskScore, 0) / results.length) : 0,
          avgConfidence: results.length > 0 ? results.reduce((s, r) => s + r.confidenceScore, 0) / results.length : 0,
          avgCoverage: results.length > 0 ? results.reduce((s, r) => s + r.coverageScore, 0) / results.length : 0,
          results: results as any,
          topFailures: results.filter(r => !r.passed).slice(0, 10).map(r => ({
            scenarioId: r.scenarioId, scenarioName: r.scenarioName,
            missingBehaviors: r.missingBehaviors, unexpectedBehaviors: r.unexpectedBehaviors,
          })),
          timestamp: new Date(),
          durationMs: results.reduce((s, r) => s + r.durationMs, 0),
        };
        console.log(renderCampaignReport(report));
        break;
      }
      case 'delete': {
        const id = args[0];
        if (!id) { console.log('Usage: sentinel network campaign delete <campaign_id>'); return; }
        this.db.deleteCampaign(id);
        console.log(`Campaign ${id} deleted.`);
        break;
      }
      default:
        console.log('Usage: sentinel network campaign <list|run|show|delete> [args]');
    }
  }

  replay(
    action: 'run' | 'campaign' | 'diff',
    ...args: string[]
  ): void {
    switch (action) {
      case 'run': {
        const filePath = args[0];
        if (!filePath) { console.log('Usage: sentinel network replay run <session.json>'); return; }
        const engine = new ReplayEngine();
        const result = engine.replayFile(filePath);
        console.log('\nReplay Result:');
        console.log(`  Session:      ${result.sessionId}`);
        console.log(`  Risk Score:   ${result.riskScore}/100`);
        console.log(`  Risk Level:   ${result.riskLevel}`);
        console.log(`  Confidence:   ${(result.confidence * 100).toFixed(0)}%`);
        console.log(`  Behaviors:    ${result.behaviorsDetected.join(', ') || '(none)'}`);
        if (result.verdict?.sessionDna) {
          console.log(`  Verdict:      ${result.verdict.sessionDna.verdictSummary}`);
        }
        if (result.errors.length > 0) {
          console.log(`  Errors:       ${result.errors.join('; ')}`);
        }
        console.log(`  Duration:     ${result.durationMs}ms`);
        break;
      }
      case 'campaign': {
        const dirPath = args[0];
        if (!dirPath) { console.log('Usage: sentinel network replay campaign <sessions-dir>'); return; }
        console.log(`Running replay campaign on ${dirPath}...`);
        const campaign = runReplayCampaign(dirPath);
        console.log(renderReplayCampaignSummary(campaign));
        break;
      }
      case 'diff': {
        const baseDir = args[0];
        const curDir = args[1];
        if (!baseDir || !curDir) { console.log('Usage: sentinel network replay diff <baseline-dir> <current-dir>'); return; }
        const { compareReplayResults, renderComparisonSummary } = require('../../core/network/replay-campaign');
        const engine = new ReplayEngine();
        console.log('Running baseline...');
        const baseFiles = require('fs').readdirSync(baseDir).filter((f: string) => f.endsWith('.json')).sort();
        const baseline = baseFiles.map((f: string) => engine.replayFile(require('path').join(baseDir, f)));
        console.log('Running current...');
        const curFiles = require('fs').readdirSync(curDir).filter((f: string) => f.endsWith('.json')).sort();
        const current = curFiles.map((f: string) => engine.replayFile(require('path').join(curDir, f)));
        const comparisons = compareReplayResults(baseline, current);
        console.log(renderComparisonSummary(comparisons));
        break;
      }
      default:
        console.log('Usage: sentinel network replay <run|campaign|diff> [args]');
    }
  }

  benchmark(action: 'history'): void {
    switch (action) {
      case 'history':
        console.log(renderBenchmarkHistory());
        break;
      default:
        console.log('Usage: sentinel network benchmark <history>');
    }
  }

  corpus(action: 'coverage', corpusDir?: string): void {
    switch (action) {
      case 'coverage': {
        const dir = corpusDir || require('path').join(process.cwd(), 'replay-corpus');
        const coverage = computeCorpusCoverage(dir);
        console.log(renderCorpusCoverage(coverage));
        break;
      }
      default:
        console.log('Usage: sentinel network corpus <coverage> [corpus_dir]');
    }
  }

  async record(
    action: 'start',
    ...args: string[]
  ): Promise<void> {
    switch (action) {
      case 'start': {
        // Parse --profile <id> flag
        const profileIdx = args.indexOf('--profile');
        let profileId: string | undefined;
        const cleanArgs: string[] = [];
        for (let i = 0; i < args.length; i++) {
          if (args[i] === '--profile' && i + 1 < args.length) {
            profileId = args[i + 1];
            i++;
          } else {
            cleanArgs.push(args[i]);
          }
        }

        const durationArg = cleanArgs[0] || '30';
        const durationMs = parseInt(durationArg, 10) * 1000;
        const outputDir = cleanArgs[1] || require('path').join(process.cwd(), 'replay-corpus', 'recorded');
        const tags = cleanArgs.slice(2);

        const label = tags.length > 0 ? tags[0] : undefined;
        const tagList = tags.length > 0 ? tags : undefined;

        console.log(`Recording session for ${durationArg}s to ${outputDir}...`);
        if (profileId) {
          const { findProfile } = require('../../core/network/canonical-sessions');
          const profile = findProfile(profileId);
          if (!profile) {
            console.log(`  Unknown profile: ${profileId}. Use one of:`);
            const { CANONICAL_PROFILES } = require('../../core/network/canonical-sessions');
            for (const p of CANONICAL_PROFILES) {
              console.log(`    ${p.id.padEnd(22)} ${p.description}`);
            }
            return;
          }
          console.log(`  Profile: ${profile.id} (${profile.category}, expected risk: ${profile.expectedRisk})`);
        }
        const recorder = new SessionRecorder();
        const session = await recorder.record({
          durationMs,
          outputDir,
          label,
          tags: tagList,
          profileId,
        });
        break;
      }
      default:
        console.log('Usage: sentinel network record start <duration_sec> [dir] [tags...] [--profile <id>]');
    }
  }
}

function rowToBlindSpot(row: Record<string, unknown>): BlindSpotEntry {
  return {
    id: row.id as string,
    title: row.title as string,
    description: (row.description as string) || '',
    howItHappened: (row.how_it_happened as string) || '',
    sensorFailed: (row.sensor_failed as string) || '',
    expectedBehavior: (row.expected_behavior as string) || '',
    actualObservation: (row.actual_observation as string) || '',
    impact: (row.impact as string) || '',
    severity: (row.severity as BlindSpotEntry['severity']) || 'medium',
    status: (row.status as BlindSpotEntry['status']) || 'open',
    sessionId: row.session_id as string | undefined,
    createdAt: new Date(row.created_at as string),
    updatedAt: new Date(row.updated_at as string),
    resolvedAt: row.resolved_at ? new Date(row.resolved_at as string) : undefined,
    resolution: row.resolution as string | undefined,
  };
}
