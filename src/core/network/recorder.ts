'use strict';

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  RecordedSession, ScenarioEvent,
  NetworkFlow, ProcessEvent, FileAccessEvent, GitCommandEvent,
  generateId
} from './types';

interface EventBuffer {
  flows: NetworkFlow[];
  processes: ProcessEvent[];
  fileAccesses: FileAccessEvent[];
  gitCommands: GitCommandEvent[];
}

export interface RecorderOptions {
  durationMs: number;
  outputDir: string;
  tags?: string[];
  pollInterval?: {
    process?: number;
    file?: number;
    git?: number;
  };
}

export class Recorder {
  private buffer: EventBuffer = { flows: [], processes: [], fileAccesses: [], gitCommands: [] };
  private running = false;
  private startTime: Date | null = null;
  private timers: ReturnType<typeof setInterval>[] = [];

  async record(options: RecorderOptions): Promise<RecordedSession> {
    this.buffer = { flows: [], processes: [], fileAccesses: [], gitCommands: [] };
    this.startTime = new Date();
    this.running = true;

    // Start process polling
    const pInterval = options.pollInterval?.process ?? 2000;
    this.timers.push(setInterval(() => this.pollProcesses(), pInterval));

    // Start file watch polling
    const fInterval = options.pollInterval?.file ?? 3000;
    this.timers.push(setInterval(() => this.pollFileAccess(), fInterval));

    // Start git detection polling
    const gInterval = options.pollInterval?.git ?? 3000;
    this.timers.push(setInterval(() => this.pollGitCommands(), gInterval));

    // Wait for duration
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        this.stop();
        resolve();
      }, options.durationMs);
      this.timers.push(timer);
    });

    const now = new Date();
    const session: RecordedSession = {
      format: 'sentinel-session-v1',
      metadata: {
        id: generateId(),
        recordedAt: this.startTime.toISOString(),
        durationMs: now.getTime() - this.startTime.getTime(),
        platform: os.platform(),
        sentinelVersion: '1.0.0',
        tags: options.tags ?? [],
      },
      private: {
        hostname: os.hostname(),
        username: os.userInfo().username,
        workingDirectory: process.cwd(),
      },
      events: this.buildEvents(),
    };

    // Write to file
    const fileName = `session-${session.metadata.id}.json`;
    const filePath = path.join(options.outputDir, fileName);
    if (!fs.existsSync(options.outputDir)) {
      fs.mkdirSync(options.outputDir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(session, null, 2), 'utf-8');
    console.log(`Session recorded: ${filePath}`);
    console.log(`  Events: ${session.events.length} (${this.buffer.flows.length} flows, ${this.buffer.processes.length} processes, ${this.buffer.fileAccesses.length} file accesses, ${this.buffer.gitCommands.length} git commands)`);

    return session;
  }

  private stop(): void {
    this.running = false;
    for (const t of this.timers) {
      clearInterval(t);
      clearTimeout(t);
    }
    this.timers = [];
  }

  private pollProcesses(): void {
    try {
      const { execSync } = require('child_process');
      let output: string;
      if (os.platform() === 'win32') {
        output = execSync('wmic process get ProcessId,Name,CommandLine,ParentProcessId /format:csv', {
          encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'ignore']
        });
      } else {
        output = execSync('ps -eo pid,ppid,comm,args --no-headers 2>/dev/null || ps -eo pid,ppid,comm,args 2>/dev/null', {
          encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'ignore']
        });
      }
      const lines = output.split('\n').filter(l => l.trim().length > 0);
      for (const line of lines) {
        const processEvent = this.parseProcessLine(line);
        if (processEvent) {
          this.buffer.processes.push(processEvent);
        }
      }
    } catch (_) {
      // silent
    }
  }

  private parseProcessLine(line: string): ProcessEvent | null {
    try {
      const proc: ProcessEvent = {
        pid: 0,
        name: 'unknown',
        commandLine: '',
        timestamp: new Date(),
        riskIndicators: [],
      };
      if (os.platform() === 'win32') {
        const parts = line.split(',');
        if (parts.length < 3) return null;
        const nameIdx = parts.findIndex(p => p === 'Name' || p === 'name');
        const pidIdx = parts.findIndex(p => p === 'ProcessId' || p === 'ProcessId' || p === 'PID');
        const cmdIdx = parts.findIndex(p => p === 'CommandLine' || p === 'CommandLine');
        if (nameIdx >= 0) proc.name = parts[nameIdx + 1] || 'unknown';
        if (pidIdx >= 0) proc.pid = parseInt(parts[pidIdx + 1] || '0', 10);
        if (cmdIdx >= 0) proc.commandLine = parts[cmdIdx + 1] || '';
      } else {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 3) return null;
        proc.pid = parseInt(parts[0], 10);
        proc.parentPid = parseInt(parts[1], 10);
        proc.name = parts[2];
        proc.commandLine = parts.slice(3).join(' ') || parts[2];
      }
      if (proc.pid > 0 && !proc.commandLine.includes('wmic') && !proc.commandLine.includes('ps -eo')) {
        return proc;
      }
      return null;
    } catch {
      return null;
    }
  }

  private pollFileAccess(): void {
    try {
      const cwd = process.cwd();
      const entries = fs.readdirSync(cwd, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isFile() || entry.isDirectory()) {
          const fp = path.join(cwd, entry.name);
          try {
            const stat = fs.statSync(fp);
            const access: FileAccessEvent = {
              filePath: fp,
              processName: 'recorder',
              pid: process.pid,
              operation: 'read',
              timestamp: new Date(),
              bytesRead: entry.isFile() ? stat.size : 0,
            };
            this.buffer.fileAccesses.push(access);
          } catch {
            // skip if we can't stat
          }
        }
      }
    } catch (_) {
      // silent
    }
  }

  private pollGitCommands(): void {
    try {
      const { execSync } = require('child_process');
      const cwd = process.cwd();
      const gitDir = path.join(cwd, '.git');
      if (fs.existsSync(gitDir)) {
        const output = execSync('git log --oneline -5 2>/dev/null', {
          encoding: 'utf-8', timeout: 3000, cwd, stdio: ['pipe', 'pipe', 'ignore']
        });
        if (output.trim()) {
          const event: GitCommandEvent = {
            pid: process.pid,
            processName: 'git',
            commandLine: 'git log --oneline -5',
            action: 'log',
            timestamp: new Date(),
            repository: cwd,
          };
          this.buffer.gitCommands.push(event);
        }
        const output2 = execSync('git status --porcelain 2>/dev/null', {
          encoding: 'utf-8', timeout: 3000, cwd, stdio: ['pipe', 'pipe', 'ignore']
        });
        if (output2.trim()) {
          const event: GitCommandEvent = {
            pid: process.pid,
            processName: 'git',
            commandLine: 'git status --porcelain',
            action: 'other',
            timestamp: new Date(),
            repository: cwd,
          };
          this.buffer.gitCommands.push(event);
        }
      }
    } catch (_) {
      // silent
    }
  }

  private buildEvents(): ScenarioEvent[] {
    const events: ScenarioEvent[] = [];

    for (const f of this.buffer.flows) {
      events.push({ type: 'flow', data: f });
    }
    for (const p of this.buffer.processes) {
      events.push({ type: 'process', data: p });
    }
    for (const f of this.buffer.fileAccesses) {
      events.push({ type: 'file_access', data: f });
    }
    for (const g of this.buffer.gitCommands) {
      events.push({ type: 'git_command', data: g });
    }

    return events;
  }
}
