'use strict';

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ProcessMonitor } from './process-monitor';
import { FileWatcher } from './file-watcher';
import { GitDetector } from './git-detector';
import { DnsObserver } from './dns-observer';
import { ConnectionInspector } from './connection-inspector';
import {
  RecordedSession, ScenarioEvent, generateId, SessionProfile, SessionEnvironment,
  NetworkFlow, ProcessEvent, FileAccessEvent, GitCommandEvent,
} from '../../core/network/types';
import { ReplayEngine } from '../../core/network/replay-engine';
import { captureEnvironment, capturePrivateMetadata, findProfile } from '../../core/network/canonical-sessions';

export interface RecordOptions {
  durationMs: number;
  outputDir: string;
  label?: string;
  tags?: string[];
  profileId?: string;
  profile?: SessionProfile;
  captureEnv?: boolean;
  pollInterval?: {
    process?: number;
    file?: number;
    git?: number;
  };
}

export class SessionRecorder {
  private buffer: { flows: NetworkFlow[]; processes: ProcessEvent[]; fileAccesses: FileAccessEvent[]; gitCommands: GitCommandEvent[] } = {
    flows: [], processes: [], fileAccesses: [], gitCommands: [],
  };
  private running = false;
  private startTime: Date | null = null;

  private processMonitor?: ProcessMonitor;
  private fileWatcher?: FileWatcher;
  private gitDetector?: GitDetector;
  private dnsObserver?: DnsObserver;
  private connectionInspector?: ConnectionInspector;

  async record(options: RecordOptions): Promise<RecordedSession> {
    this.buffer = { flows: [], processes: [], fileAccesses: [], gitCommands: [] };
    this.startTime = new Date();
    this.running = true;

    // Start process monitor
    this.processMonitor = new ProcessMonitor(options.pollInterval?.process ?? 100);
    this.processMonitor.start((event) => {
      if (!this.running) return;
      this.buffer.processes.push(event);
    });

    // Start file watcher
    this.fileWatcher = new FileWatcher(options.pollInterval?.file ?? 3000);
    this.fileWatcher.addWatchPath(process.cwd());
    this.fileWatcher.start((event) => {
      if (!this.running) return;
      this.buffer.fileAccesses.push(event);
    });

    // Start git detector
    this.gitDetector = new GitDetector(options.pollInterval?.git ?? 100);
    this.gitDetector.start((event) => {
      if (!this.running) return;
      this.buffer.gitCommands.push(event);
    });

    // Start DNS observer
    this.dnsObserver = new DnsObserver();
    this.dnsObserver.start('recorder', (flow) => {
      if (!this.running) return;
      this.buffer.flows.push(flow);
    });

    // Start connection inspector
    this.connectionInspector = new ConnectionInspector();
    this.connectionInspector.start('recorder', (flow) => {
      if (!this.running) return;
      this.buffer.flows.push(flow);
    });

    console.log(`Recording for ${(options.durationMs / 1000).toFixed(0)}s...`);

    // Wait for duration
    await new Promise<void>(resolve => setTimeout(resolve, options.durationMs));

    this.stop();

    const now = new Date();
    const profile = options.profile ?? (options.profileId ? findProfile(options.profileId) : undefined);
    const session: RecordedSession = {
      format: 'sentinel-session-v1',
      metadata: {
        id: options.label ? `${options.label}-${generateId()}` : generateId(),
        recordedAt: this.startTime.toISOString(),
        durationMs: now.getTime() - this.startTime.getTime(),
        platform: os.platform(),
        sentinelVersion: '1.0.0',
        tags: options.tags ?? [],
        profile: profile,
        environment: options.captureEnv !== false ? captureEnvironment() : undefined,
      },
      private: options.captureEnv !== false ? capturePrivateMetadata() : undefined,
      events: [
        ...this.buffer.flows.map(f => ({ type: 'flow' as const, data: f })),
        ...this.buffer.processes.map(p => ({ type: 'process' as const, data: p })),
        ...this.buffer.fileAccesses.map(f => ({ type: 'file_access' as const, data: f })),
        ...this.buffer.gitCommands.map(g => ({ type: 'git_command' as const, data: g })),
      ],
    };

    // Write to file
    if (!fs.existsSync(options.outputDir)) {
      fs.mkdirSync(options.outputDir, { recursive: true });
    }
    const fileName = `session-${session.metadata.id}.json`;
    const filePath = path.join(options.outputDir, fileName);
    fs.writeFileSync(filePath, JSON.stringify(session, null, 2), 'utf-8');

    console.log(`\nSession saved: ${filePath}`);
    console.log(`  Events: ${session.events.length} (${this.buffer.flows.length} flows, ${this.buffer.processes.length} processes, ${this.buffer.fileAccesses.length} file accesses, ${this.buffer.gitCommands.length} git commands)`);

    // Write ground truth alongside session
    if (profile) {
      const gtPath = filePath.replace(/\.json$/, '.ground-truth.json');
      const groundTruth: import('../../core/network/types').SessionGroundTruth = {
        profileId: profile.id,
        expectedRisk: profile.expectedRisk,
        expectedBehaviors: [],
        forbiddenBehaviors: profile.expectedRisk === 'LOW'
          ? ['code_upload', 'secrets_exfiltrated', 'full_repo_snapshot', 'dns_suspicious', 'credential_access']
          : [],
        reviewedBy: 'automated',
        reviewStatus: 'unreviewed',
      };
      fs.writeFileSync(gtPath, JSON.stringify(groundTruth, null, 2), 'utf-8');
      console.log(`  Ground truth: ${gtPath}`);
    }

    // Replay through pipeline for immediate feedback
    console.log('\nReplaying through pipeline...');
    try {
      const engine = new ReplayEngine();
      const result = engine.replay(session);
      console.log(`  Risk: ${result.riskLevel} (${result.riskScore}/100)`);
      console.log(`  Behaviors: ${result.behaviorsDetected.join(', ') || '(none)'}`);
      if (result.errors.length > 0) {
        console.log(`  Errors: ${result.errors.join('; ')}`);
      }
    } catch (err: any) {
      console.log(`  Pipeline error: ${err.message}`);
    }

    return session;
  }

  private stop(): void {
    this.running = false;
    this.processMonitor?.stop();
    this.fileWatcher?.stop();
    this.gitDetector?.stop();
    this.dnsObserver?.stop();
    this.connectionInspector?.stop();
  }
}
