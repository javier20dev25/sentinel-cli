'use strict';

import * as child_process from 'child_process';
import * as os from 'os';
import * as path from 'path';
import { GitCommandEvent } from '../../core/network/types';

export class GitDetector {
  private intervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private onEvent: ((event: GitCommandEvent) => void) | null = null;
  private knownPids: Set<number> = new Set();
  private previousCwd: string = '';
  private monitorProcess: child_process.ChildProcess | null = null;

  constructor(intervalMs = 100) {
    this.intervalMs = intervalMs;
  }

  start(callback: (event: GitCommandEvent) => void): void {
    this.onEvent = callback;
    this.detectCurrentRepo();

    if (os.platform() === 'win32') {
      this.startWindowsMonitor();
    } else {
      this.timer = setInterval(() => this.pollLinux(), this.intervalMs);
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.monitorProcess) {
      this.monitorProcess.kill();
      this.monitorProcess = null;
    }
    this.knownPids.clear();
  }

  private detectCurrentRepo(): void {
    try {
      const cwd = process.cwd();
      const out = child_process.execSync(
        'git rev-parse --show-toplevel 2>nul',
        { timeout: 3000, encoding: 'utf8', cwd }
      ).trim();
      if (out) {
        this.previousCwd = out;
      }
    } catch {
    }
  }

  /**
   * Windows: spawn a persistent PowerShell process that polls for new git.exe
   * processes every 50ms and outputs each as a JSON line. This is much more
   * responsive than setInterval + execSync (which spawns a new PowerShell
   * each time) and captured 7 git commands in testing vs 0 with execSync.
   */
  private startWindowsMonitor(): void {
    const scriptContent = [
      '$seen = New-Object System.Collections.Generic.HashSet[int]',
      'while($true) {',
      '  try {',
      '    $procs = Get-CimInstance Win32_Process -Filter "Name=\'git.exe\'" -ErrorAction Stop',
      '    foreach($p in $procs) {',
      '      if($p.ProcessId -and $seen.Add($p.ProcessId)) {',
      '        $o = [PSCustomObject]@{ ProcessId=$p.ProcessId; Name=$p.Name; CommandLine=$p.CommandLine }',
      '        $o | ConvertTo-Json -Compress',
      '      }',
      '    }',
      '  } catch {}',
      '  Start-Sleep -Milliseconds 100',
      '}',
    ].join('\n');

    this.monitorProcess = child_process.spawn('powershell', [
      '-NoProfile', '-NonInteractive',
      '-ExecutionPolicy', 'Bypass',
      '-Command', scriptContent,
    ], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });

    const mp = this.monitorProcess;
    if (!mp) return;

    let buffer = '';
    mp.stdout!.on('data', (data: Buffer) => {
      buffer += data.toString('utf8');
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const p = JSON.parse(trimmed);
          if (p && p.ProcessId) {
            const pid = p.ProcessId as number;
            if (!this.knownPids.has(pid)) {
              this.knownPids.add(pid);
              const name = (p.Name as string) || 'git.exe';
              const cmd = (p.CommandLine as string) || '';
              const action = this.classifyGitAction(cmd);
              this.emit(pid, name, cmd, action || 'other');
            }
          }
        } catch {}
      }
    });

    mp.stderr!.on('data', () => {}); // ignore stderr
    mp.on('exit', () => {
      this.monitorProcess = null;
      // Restart if stopped unexpectedly
      if (this.onEvent) {
        this.startWindowsMonitor();
      }
    });
  }

  private pollLinux(): void {
    const out = child_process.execSync(
      'ps -eo pid,comm,args --no-headers 2>/dev/null | grep -i " git " | head -50',
      { timeout: 3000, encoding: 'utf8' }
    ).trim();
    if (!out) return;

    for (const line of out.split('\n')) {
      const parts = line.trim().split(/\s+/);
      const pid = parseInt(parts[0], 10) || 0;
      if (this.knownPids.has(pid)) continue;
      this.knownPids.add(pid);

      const name = parts[1] || '';
      const cmd = parts.slice(2).join(' ') || '';
      const action = this.classifyGitAction(cmd);
      this.emit(pid, name, cmd, action || 'other');
    }
  }

  private classifyGitAction(cmd: string): GitCommandEvent['action'] | null {
    const lower = cmd.toLowerCase();
    // Tokenize by whitespace, then strip surrounding quotes from each token
    const tokens = lower.split(/\s+/).map(t => t.replace(/^["']|["']$/g, ''));
    const gitIdx = tokens.findIndex(t => t === 'git' || t === 'git.exe' || t.endsWith('\\git.exe') || t.endsWith('/git'));
    if (gitIdx < 0 || gitIdx + 1 >= tokens.length) return null;
    // Skip git global options (starting with -) to find the subcommand
    let subCmdIdx = gitIdx + 1;
    while (subCmdIdx < tokens.length && tokens[subCmdIdx].startsWith('-')) {
      // If it's a flag with a value (like -c key=val), skip the value too
      if (tokens[subCmdIdx] === '-c' && subCmdIdx + 1 < tokens.length) subCmdIdx++;
      subCmdIdx++;
    }
    if (subCmdIdx >= tokens.length) return null;
    const subCmd = tokens[subCmdIdx];

    switch (subCmd) {
      case 'clone': return 'clone';
      case 'fetch': return 'fetch';
      case 'push': return 'push';
      case 'pull': return 'pull';
      case 'log': return 'log';
      case 'diff': return 'diff';
      case 'status': return 'status';
      case 'add': return 'add';
      case 'commit': return 'commit';
      case 'checkout': return 'checkout';
      case 'branch': return 'branch';
      case 'merge': return 'merge';
      case 'rebase': return 'rebase';
      case 'init': return 'init';
      case 'config': return 'config';
      case 'remote': return 'remote';
      case 'rev-list': return 'rev-list';
      case 'rev-parse': return 'rev-parse';
      case 'bundle': return 'bundle';
      case 'archive': return 'archive';
      case 'pack-objects': return 'pack';
      case 'cat-file': return 'cat-file';
      case 'ls-tree': return 'ls-tree';
      case 'show-ref': return 'show-ref';
      case 'for-each-ref': return 'for-each-ref';
      case 'stash': return 'stash';
      case 'tag': return 'tag';
      case 'reset': return 'reset';
      case 'revert': return 'revert';
      case 'cherry-pick': return 'cherry-pick';
      case 'clean': return 'clean';
      case 'submodule': return 'submodule';
      case 'worktree': return 'worktree';
      case 'gc': return 'gc';
      case 'fsck': return 'fsck';
      default: return 'other';
    }
  }

  private emit(pid: number, name: string, cmd: string, action: GitCommandEvent['action']): void {
    if (!this.onEvent) return;

    let repo: string | undefined;
    const parts = cmd.split(/\s+/);
    for (let i = 0; i < parts.length; i++) {
      if (parts[i] === '--repo' || parts[i] === '-C') {
        repo = parts[i + 1];
        break;
      }
    }
    if (!repo && this.previousCwd) {
      repo = this.previousCwd;
    }

    this.onEvent({
      pid,
      processName: name,
      commandLine: cmd,
      action,
      timestamp: new Date(),
      repository: repo,
    });
  }
}
