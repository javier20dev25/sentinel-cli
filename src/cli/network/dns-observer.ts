'use strict';

import * as child_process from 'child_process';
import * as os from 'os';
import { NetworkFlow, generateId } from '../../core/network/types';

export class DnsObserver {
  private intervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private onFlow: ((flow: NetworkFlow) => void) | null = null;
  private sessionId: string = '';
  private platform: string;
  private seenEntries: Set<string> = new Set();
  private baselineTaken: boolean = false;

  constructor(intervalMs = 2000) {
    this.intervalMs = intervalMs;
    this.platform = os.platform();
  }

  start(sessionId: string, callback: (flow: NetworkFlow) => void): void {
    this.sessionId = sessionId;
    this.onFlow = callback;
    // First poll establishes baseline — no emissions
    this.takeBaseline();
    this.timer = setInterval(() => this.poll(), this.intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private takeBaseline(): void {
    try {
      const entries = this.getDnsCache();
      for (const q of entries) {
        this.seenEntries.add(q);
      }
      this.baselineTaken = true;
    } catch {
      this.baselineTaken = true;
    }
  }

  private getDnsCache(): string[] {
    if (this.platform !== 'win32') return [];
    const out = child_process.execSync(
      'cmd.exe /c "ipconfig /displaydns"',
      { timeout: 3000, encoding: 'utf8', maxBuffer: 5 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] }
    );
    if (!out) return [];
    const result: string[] = [];
    const domainRegex = /^\s+\S[^:]*\s*\.\s*:\s*(\S+(?:\.\S+)+)\s*$/;
    const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    for (const line of out.split('\n')) {
      const m = line.match(domainRegex);
      if (m && !ipRegex.test(m[1])) {
        result.push(m[1]);
      }
    }
    return result;
  }

  private poll(): void {
    try {
      if (this.platform === 'win32') {
        this.pollWindows();
      } else {
        this.pollLinux();
      }
    } catch {
    }
  }

  private pollWindows(): void {
    const current = this.getDnsCache();
    for (const query of current) {
      if (this.seenEntries.has(query)) continue;
      this.seenEntries.add(query);
      if (this.isSuspiciousDns(query)) {
        this.emitFlow(query, []);
      }
    }
  }

  private pollLinux(): void {
    try {
      const out = child_process.execSync(
        'cat /proc/net/udp /proc/net/tcp 2>/dev/null | head -100',
        { timeout: 2000, encoding: 'utf8' }
      );
    } catch {
    }
    const out = child_process.execSync(
      'nslookup google.com 2>/dev/null | head -5 || true',
      { timeout: 2000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
  }

  private isSuspiciousDns(query: string): boolean {
    const lower = query.toLowerCase();
    const patterns = [
      '.grok.com', '.x.ai', '.openai.com', '.anthropic.com',
      '.googleapis.com', 'storage.googleapis.com',
      '.githubcopilot.com', '.cursor.sh', '.claude.ai',
      '.tabby.sh', '.continue.dev',
      'pastebin.com', 'discord.com', 'gist.github.com',
      'httpbin.org', 'webhook.site', 'requestbin.com',
      'pipedream.com', 'ngrok.io', 'hookbin.com',
      'beacon.this', 'canarytokens.com',
    ];
    return patterns.some(p => lower.includes(p));
  }

  private emitFlow(query: string, responses: string[]): void {
    if (!this.onFlow) return;
    this.onFlow({
      id: generateId(),
      sessionId: this.sessionId,
      timestamp: new Date(),
      protocol: 'DNS',
      sourceAddr: '127.0.0.1',
      sourcePort: 0,
      destAddr: '8.8.8.8',
      destPort: 53,
      hostname: query,
      dnsQuery: query,
      dnsResponse: responses,
      bytesSent: query.length,
      bytesReceived: responses.join(',').length,
      durationMs: 0,
    });
  }
}
