'use strict';

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { FileAccessEvent } from '../../core/network/types';

export class FileWatcher {
  private watchedPaths: string[] = [];
  private intervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private onEvent: ((event: FileAccessEvent) => void) | null = null;
  private previousSnapshot: Map<string, number> = new Map();
  private platform: string;

  constructor(intervalMs = 3000) {
    this.intervalMs = intervalMs;
    this.platform = os.platform();
  }

  addWatchPath(p: string): void {
    if (!this.watchedPaths.includes(p)) {
      this.watchedPaths.push(p);
    }
    this.updateSnapshot();
  }

  start(callback: (event: FileAccessEvent) => void): void {
    this.onEvent = callback;
    this.discoverGitDirs();
    this.updateSnapshot();
    this.timer = setInterval(() => this.poll(), this.intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.previousSnapshot.clear();
  }

  private discoverGitDirs(): void {
    const searchPaths = [process.cwd(), os.homedir()];
    for (const base of searchPaths) {
      try {
        const items = fs.readdirSync(base);
        for (const item of items) {
          if (item === '.git') {
            const gitPath = path.join(base, item);
            if (fs.statSync(gitPath).isDirectory()) {
              this.watchedPaths.push(gitPath);
            }
          } else if (item === '.cursor' || item === '.vscode') {
            this.watchedPaths.push(path.join(base, item));
          }
        }
      } catch {
      }
    }
  }

  private updateSnapshot(): void {
    for (const wp of this.watchedPaths) {
      this.scanDir(wp);
    }
  }

  private scanDir(dir: string): void {
    try {
      if (!fs.existsSync(dir)) return;
      const items = fs.readdirSync(dir, { withFileTypes: true });
      for (const item of items) {
        const fullPath = path.join(dir, item.name);
        try {
          const stat = fs.statSync(fullPath);
          const key = fullPath;
          const prevSize = this.previousSnapshot.get(key) || 0;

          if (stat.isDirectory()) {
            const subPath = fullPath;
            if (!this.previousSnapshot.has(subPath)) {
              this.previousSnapshot.set(subPath, 0);
            }
            this.scanDir(subPath);
          } else if (stat.size !== prevSize) {
            this.previousSnapshot.set(key, stat.size);
          }
        } catch {
        }
      }
    } catch {
    }
  }

  private poll(): void {
    for (const wp of this.watchedPaths) {
      try {
        if (!fs.existsSync(wp)) continue;
        const items = fs.readdirSync(wp, { withFileTypes: true });
        for (const item of items) {
          const fullPath = path.join(wp, item.name);
          try {
            const stat = fs.statSync(fullPath);
            const key = fullPath;
            const prevSize = this.previousSnapshot.get(key) || 0;

            if (item.name.endsWith('.bundle') && !this.previousSnapshot.has(key)) {
              this.previousSnapshot.set(key, stat.size);
              if (this.onEvent) {
                this.onEvent({
                  filePath: fullPath,
                  processName: 'filesystem',
                  pid: 0,
                  operation: 'create',
                  timestamp: new Date(),
                  bytesRead: stat.size,
                });
              }
              continue;
            }
            this.previousSnapshot.set(key, stat.size);
          } catch {
          }
        }
      } catch {
      }
    }
  }
}
