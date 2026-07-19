'use strict';

import * as os from 'os';
import * as child_process from 'child_process';
import { ProcessEvent } from '../../core/network/types';

interface ProcessEntry {
  pid: number;
  name: string;
  cmdline: string;
  ppid?: number;
  pname?: string;
  user?: string;
}

export class ProcessMonitor {
  private knownPids: Set<number> = new Set();
  private intervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private onEvent: ((event: ProcessEvent) => void) | null = null;
  private platform: string;

  constructor(intervalMs = 100) {
    this.intervalMs = intervalMs;
    this.platform = os.platform();
  }

  start(callback: (event: ProcessEvent) => void): void {
    this.onEvent = callback;
    this.poll();
    this.timer = setInterval(() => this.poll(), this.intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.knownPids.clear();
  }

  private poll(): void {
    try {
      const procs = this.getProcessList();
      for (const proc of procs) {
        if (this.knownPids.has(proc.pid)) continue;
        this.knownPids.add(proc.pid);

        if (this.onEvent) {
          this.onEvent({
            pid: proc.pid,
            name: proc.name,
            commandLine: proc.cmdline,
            parentPid: proc.ppid,
            parentName: proc.pname,
            timestamp: new Date(),
            username: proc.user,
            riskIndicators: this.checkRiskIndicators(proc),
          });
        }
      }
    } catch {
    }
  }

  private getProcessList(): ProcessEntry[] {
    try {
      if (this.platform === 'win32') {
        return this.getWindowsProcesses();
      } else {
        return this.getLinuxProcesses();
      }
    } catch {
      return [];
    }
  }

  private getWindowsProcesses(): ProcessEntry[] {
    const out = child_process.execSync(
      'powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ParentProcessId, ExecutablePath | ConvertTo-JSON"',
      { timeout: 5000, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
    );
    const parsed = JSON.parse(out);
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    return arr.filter((p: Record<string, unknown>) => p && p.ProcessId).map((p: Record<string, unknown>) => ({
      pid: p.ProcessId as number,
      name: (p.Name as string) || '',
      cmdline: (p.CommandLine as string) || '',
      ppid: p.ParentProcessId as number | undefined,
    }));
  }

  private getLinuxProcesses(): ProcessEntry[] {
    const out = child_process.execSync(
      'ps -eo pid,comm,args,ppid,user --no-headers 2>/dev/null | head -500',
      { timeout: 3000, encoding: 'utf8' }
    );
    return out.split('\n').filter(Boolean).map(line => {
      const parts = line.trim().split(/\s+/);
      return {
        pid: parseInt(parts[0], 10) || 0,
        name: parts[1] || '',
        cmdline: parts.slice(2).join(' ') || '',
        ppid: parseInt(parts[parts.length - 2], 10),
        user: parts[parts.length - 1],
      };
    }).filter(p => p.pid > 0);
  }

  private checkRiskIndicators(proc: ProcessEntry): string[] {
    const indicators: string[] = [];
    const cmdLower = proc.cmdline.toLowerCase();
    const nameLower = proc.name.toLowerCase();

    // Skip legitimate system processes that have AI-adjacent names
    // (e.g. Microsoft Copilot system service runs from C:\Program Files\Microsoft\Copilot\)
    if (cmdLower.includes('\\microsoft\\copilot\\')) {
      return [];
    }

    const aiAgents = ['grok', 'cursor', 'copilot', 'claude', 'codex', 'gemini',
      'continue', 'tabby', 'tabnine', 'codeium', 'windsurf', 'aider'];
    for (const agent of aiAgents) {
      if (nameLower.includes(agent) || cmdLower.includes(agent)) {
        indicators.push(`AI agent process: ${proc.name}`);
        break;
      }
    }

    const dangerousCmds = ['git bundle', 'git archive', 'git rev-list --all',
      'git pack-objects', 'git clone --mirror', 'git clone --bare',
      'curl', 'wget', 'gcloud storage', 'gsutil', 'aws s3',
      'nslookup', 'whoami', 'ipconfig', 'netstat', 'hostname', 'arp', 'route', 'systeminfo'];
    for (const cmd of dangerousCmds) {
      if (cmdLower.includes(cmd)) {
        indicators.push(`Suspicious command: ${cmd}`);
      }
    }

    return indicators;
  }
}
