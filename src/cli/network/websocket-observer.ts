'use strict';

import * as crypto from 'crypto';
import { NetworkFlow, WebSocketFrame, generateId } from '../../core/network/types';

export class WebSocketObserver {
  private managedFlows: Map<string, {
    hostname: string;
    startTime: Date;
    frames: WebSocketFrame[];
    totalBytes: number;
  }> = new Map();

  private onFlow: ((flow: NetworkFlow) => void) | null = null;
  private sessionId: string = '';

  constructor() {
  }

  start(sessionId: string, callback: (flow: NetworkFlow) => void): void {
    this.sessionId = sessionId;
    this.onFlow = callback;
  }

  stop(): void {
    this.finalizeOpenFlows();
    this.managedFlows.clear();
  }

  reportConnection(hostname: string, path: string): string {
    const flowId = generateId();
    this.managedFlows.set(flowId, {
      hostname: `${hostname}${path}`,
      startTime: new Date(),
      frames: [],
      totalBytes: 0,
    });
    return flowId;
  }

  reportFrame(flowId: string, opcode: number, payload: Buffer | string): void {
    const flow = this.managedFlows.get(flowId);
    if (!flow) return;

    const len = typeof payload === 'string' ? Buffer.byteLength(payload) : payload.length;
    flow.frames.push({
      opcode,
      payload: typeof payload === 'string' ? payload : payload.toString('hex').substring(0, 100),
      length: len,
      timestamp: new Date(),
    });
    flow.totalBytes += len;
  }

  closeFlow(flowId: string): void {
    const flow = this.managedFlows.get(flowId);
    if (!flow || !this.onFlow) return;

    const duration = Date.now() - flow.startTime.getTime();

    this.onFlow({
      id: flowId,
      sessionId: this.sessionId,
      timestamp: flow.startTime,
      protocol: 'WS',
      sourceAddr: '127.0.0.1',
      sourcePort: 0,
      destAddr: flow.hostname,
      destPort: 443,
      hostname: flow.hostname,
      bytesSent: flow.totalBytes,
      bytesReceived: 0,
      durationMs: duration,
      wsFrames: flow.frames,
    });

    this.managedFlows.delete(flowId);
  }

  private finalizeOpenFlows(): void {
    if (!this.onFlow) return;
    for (const [flowId, flow] of this.managedFlows.entries()) {
      const duration = Date.now() - flow.startTime.getTime();
      this.onFlow({
        id: flowId,
        sessionId: this.sessionId,
        timestamp: flow.startTime,
        protocol: 'WS',
        sourceAddr: '127.0.0.1',
        sourcePort: 0,
        destAddr: flow.hostname,
        destPort: 443,
        hostname: flow.hostname,
        bytesSent: flow.totalBytes,
        bytesReceived: 0,
        durationMs: duration,
        wsFrames: flow.frames,
      });
    }
  }
}
