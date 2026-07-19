'use strict';

import * as child_process from 'child_process';
import * as os from 'os';
import { NetworkFlow, generateId } from '../../core/network/types';

export class ConnectionInspector {
  private intervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private onFlow: ((flow: NetworkFlow) => void) | null = null;
  private sessionId: string = '';
  private knownFlows: Set<string> = new Set();
  private platform: string;

  constructor(intervalMs = 500) {
    this.intervalMs = intervalMs;
    this.platform = os.platform();
  }

  start(sessionId: string, callback: (flow: NetworkFlow) => void): void {
    this.sessionId = sessionId;
    this.onFlow = callback;
    this.poll();
    this.timer = setInterval(() => this.poll(), this.intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.knownFlows.clear();
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
    const out = child_process.execSync(
      'cmd.exe /c "netstat -ano"',
      { timeout: 3000, encoding: 'utf8', maxBuffer: 5 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] }
    );
    if (!out || out === 'null') return;

    for (const line of out.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('TCP')) continue;
      if (!trimmed.includes('ESTABLISHED') && !trimmed.includes('TIME_WAIT') && !trimmed.includes('CLOSE_WAIT')) continue;

      const parts = trimmed.split(/\s+/);
      if (parts.length < 5) continue;

      const localPart = parts[1];
      const remotePart = parts[2];
      if (!localPart || !remotePart) continue;

      const localColon = localPart.lastIndexOf(':');
      const remoteColon = remotePart.lastIndexOf(':');
      if (localColon < 0 || remoteColon < 0) continue;

      const localAddr = localPart.substring(0, localColon);
      const localPort = parseInt(localPart.substring(localColon + 1), 10);
      const remoteAddr = remotePart.substring(0, remoteColon);
      const remotePort = parseInt(remotePart.substring(remoteColon + 1), 10);

      const flowKey = `${localAddr}:${localPort}-${remoteAddr}:${remotePort}`;
      if (this.knownFlows.has(flowKey)) continue;
      this.knownFlows.add(flowKey);

      if (this.isPrivateIp(remoteAddr)) continue;
      if (!this.isSuspiciousPort(remotePort)) continue;

      this.emitFlow('TCP', localAddr, localPort, remoteAddr, remotePort, undefined, undefined);
    }
  }

  private pollLinux(): void {
    const out = child_process.execSync(
      'ss -tunp state established 2>/dev/null | tail -n +2 | head -100',
      { timeout: 3000, encoding: 'utf8' }
    ).trim();
    if (!out) return;

    for (const line of out.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 5) continue;

      const local = parts[4];
      const remote = parts[5];
      if (!local || !remote) continue;

      const flowKey = `${local}-${remote}`;
      if (this.knownFlows.has(flowKey)) continue;
      this.knownFlows.add(flowKey);

      const [localAddr, localPortStr] = local.split(':');
      const [remoteAddr, remotePortStr] = remote.split(':');
      const remotePort = parseInt(remotePortStr, 10);

      if (this.isPrivateIp(remoteAddr)) continue;
      if (!this.isSuspiciousPort(remotePort)) continue;

      this.emitFlow(
        'TCP', localAddr, parseInt(localPortStr, 10) || 0,
        remoteAddr, remotePort, undefined, undefined
      );
    }
  }

  private isPrivateIp(ip: string): boolean {
    if (ip === '127.0.0.1' || ip === '::1') return true;
    if (ip.startsWith('10.')) return true;
    if (ip.startsWith('192.168.')) return true;
    if (ip.startsWith('172.')) {
      const secondOctet = parseInt(ip.split('.')[1], 10);
      if (secondOctet >= 16 && secondOctet <= 31) return true;
    }
    return false;
  }

  private isSuspiciousPort(port: number): boolean {
    return port === 443 || port === 80 || port === 8443 ||
           port === 8080 || port === 3000 || port === 5000 ||
           (port >= 1024 && port <= 49151);
  }

  private emitFlow(
    protocol: string, srcAddr: string, srcPort: number,
    destAddr: string, destPort: number,
    tlsVersion?: string, sni?: string
  ): void {
    if (!this.onFlow) return;
    this.onFlow({
      id: generateId(),
      sessionId: this.sessionId,
      timestamp: new Date(),
      protocol: 'TCP',
      sourceAddr: srcAddr,
      sourcePort: srcPort,
      destAddr,
      destPort,
      tlsVersion,
      sni,
      bytesSent: 0,
      bytesReceived: 0,
      durationMs: 0,
    });
  }
}
