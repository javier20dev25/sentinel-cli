'use strict';

import {
  NetworkFlow, FileAccessEvent, ProcessEvent,
  AntiEvasionSignal, AntiEvasionSignalType,
  Behavior, BehaviorType, generateId
} from './types';

const SIGNAL_WEIGHTS: Record<AntiEvasionSignalType, number> = {
  artificial_rhythm: 20,
  fragmented_traffic: 25,
  protocol_hopping: 30,
  custom_compression: 20,
  monitor_awareness: 40,
  memory_only_ops: 25,
  distributed_chain: 35,
  no_temp_files: 15,
  preparation_phase: 30,
  process_chain: 35,
};

function classifySignalSeverity(score: number): BehaviorType {
  if (score >= 30) return 'anti_evasion_detected';
  return 'process_suspicious';
}

export class AntiEvasionEngine {
  private previousProcessCount = 0;
  private previousFlows: Map<string, { count: number; bytes: number; interval: number[] }> = new Map();
  private baselineBehavior: Map<string, { avgReadsPerMin: number; avgFlowsPerMin: number }> = new Map();
  private sessionStartTime: Date | null = null;
  private processSnapshots: Map<number, { name: string; firstSeen: number; accessCount: number }> = new Map();

  start(sessionStart: Date): void {
    this.sessionStartTime = sessionStart;
  }

  setBaseline(processName: string, avgReadsPerMin: number, avgFlowsPerMin: number): void {
    this.baselineBehavior.set(processName, { avgReadsPerMin, avgFlowsPerMin });
  }

  evaluateFlows(
    flows: NetworkFlow[], sessionId: string
  ): AntiEvasionSignal[] {
    const signals: AntiEvasionSignal[] = [];

    const fragSig = this.detectFragmentedTraffic(flows, sessionId);
    if (fragSig) signals.push(fragSig);

    const hopSig = this.detectProtocolHopping(flows, sessionId);
    if (hopSig) signals.push(hopSig);

    const distSig = this.detectDistributedChain(flows, sessionId);
    if (distSig) signals.push(distSig);

    return signals;
  }

  evaluateFileAccesses(
    events: FileAccessEvent[], sessionId: string
  ): AntiEvasionSignal[] {
    const signals: AntiEvasionSignal[] = [];

    const rhythmSig = this.detectArtificialRhythm(events, sessionId);
    if (rhythmSig) signals.push(rhythmSig);

    const memSig = this.detectMemoryOnlyOps(events, sessionId);
    if (memSig) signals.push(memSig);

    const noTempSig = this.detectNoTempFiles(events, sessionId);
    if (noTempSig) signals.push(noTempSig);

    return signals;
  }

  evaluateProcesses(
    processes: ProcessEvent[], sessionId: string
  ): AntiEvasionSignal[] {
    const signals: AntiEvasionSignal[] = [];

    const chainSig = this.detectProcessChain(processes, sessionId);
    if (chainSig) signals.push(chainSig);

    // Note: Preparation phase detection is deliberately not done here —
    // it is handled by classifyPreparationCommands in behavior-engine.ts
    // to avoid double-counting prep commands (once as anti_evasion_detected
    // and once as preparation_detected).

    return signals;
  }

  detectMonitorAwareness(
    context: { running: boolean; elapsedMs: number },
    currentProcessCount: number,
    sessionId: string
  ): AntiEvasionSignal | null {
    if (!context.running || context.elapsedMs < 10000) return null;
    if (this.previousProcessCount === 0) {
      this.previousProcessCount = currentProcessCount;
      return null;
    }

    const drop = this.previousProcessCount - currentProcessCount;
    if (drop > 5 && currentProcessCount < this.previousProcessCount * 0.5) {
      this.previousProcessCount = currentProcessCount;
      return {
        id: generateId(),
        sessionId,
        type: 'monitor_awareness',
        score: 40,
        confidence: 0.7,
        timestamp: new Date(),
        evidence: [
          `Process count dropped from ${this.previousProcessCount} to ${currentProcessCount}`,
          `Suspicious silence after monitor start`
        ],
        details: { previous: this.previousProcessCount, current: currentProcessCount, drop }
      };
    }

    this.previousProcessCount = currentProcessCount;
    return null;
  }

  computeAntiEvasionScore(signals: AntiEvasionSignal[]): number {
    if (signals.length === 0) return 0;
    let score = 0;
    for (const s of signals) {
      score += SIGNAL_WEIGHTS[s.type] * s.confidence;
    }
    return Math.min(100, Math.round(score));
  }

  summarizeSignals(signals: AntiEvasionSignalType[]): string {
    if (signals.length === 0) return 'No evasion signals detected';
    return signals.map(s => s.replace(/_/g, ' ')).join(', ');
  }

  private detectFragmentedTraffic(
    flows: NetworkFlow[], sessionId: string
  ): AntiEvasionSignal | null {
    const externalFlows = flows.filter(f =>
      !f.destAddr.startsWith('10.') &&
      !f.destAddr.startsWith('192.168.') &&
      !f.destAddr.startsWith('172.')
    );

    if (externalFlows.length < 10) return null;

    const groupedByDest = new Map<string, NetworkFlow[]>();
    for (const f of externalFlows) {
      const key = `${f.destAddr}:${f.destPort}`;
      if (!groupedByDest.has(key)) groupedByDest.set(key, []);
      groupedByDest.get(key)!.push(f);
    }

    for (const [dest, group] of groupedByDest) {
      if (group.length < 5) continue;
      const totalBytes = group.reduce((s, f) => s + f.bytesSent, 0);
      if (totalBytes < 1024 * 1024) continue;

      const avgChunk = totalBytes / group.length;
      const chunkRatio = avgChunk / totalBytes;
      const timeSpan = group[group.length - 1].timestamp.getTime() - group[0].timestamp.getTime();
      const isSlow = timeSpan > 60000 && group.length > 20;

      if (avgChunk < 50000 && isSlow) {
        return {
          id: generateId(),
          sessionId,
          type: 'fragmented_traffic',
          score: 25,
          confidence: Math.min(0.5 + group.length * 0.02, 0.9),
          timestamp: new Date(),
          evidence: [
            `${group.length} chunks to ${dest} avg ${(avgChunk / 1024).toFixed(1)}KB`,
            `${totalBytes} bytes over ${(timeSpan / 1000).toFixed(0)}s`
          ],
          details: { destination: dest, chunks: group.length, avgChunk, totalBytes, timeSpan }
        };
      }
    }

    return null;
  }

  private detectProtocolHopping(
    flows: NetworkFlow[], sessionId: string
  ): AntiEvasionSignal | null {
    if (flows.length < 6) return null;

    const sorted = [...flows].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    const protocols: string[] = [];
    for (const f of sorted) {
      const last = protocols[protocols.length - 1];
      if (f.protocol !== last) protocols.push(f.protocol);
    }

    if (protocols.length >= 3) {
      const timeWindow = sorted[sorted.length - 1].timestamp.getTime() - sorted[0].timestamp.getTime();
      if (timeWindow < 120000) {
        return {
          id: generateId(),
          sessionId,
          type: 'protocol_hopping',
          score: 30,
          confidence: Math.min(0.5 + protocols.length * 0.1, 0.95),
          timestamp: new Date(),
          evidence: [
            `Protocol changes: ${protocols.join(' → ')}`,
            `${protocols.length} different protocols in ${(timeWindow / 1000).toFixed(0)}s`
          ],
          details: { protocols, changes: protocols.length, timeWindow }
        };
      }
    }

    return null;
  }

  private detectArtificialRhythm(
    events: FileAccessEvent[], sessionId: string
  ): AntiEvasionSignal | null {
    if (events.length < 20) return null;

    const sorted = [...events].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    const intervals: number[] = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push(sorted[i].timestamp.getTime() - sorted[i - 1].timestamp.getTime());
    }

    const avg = intervals.reduce((s, v) => s + v, 0) / intervals.length;
    if (avg < 10) return null;

    const variance = intervals.reduce((s, v) => s + (v - avg) ** 2, 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    const cv = stdDev / avg;

    if (cv < 0.15 && avg > 5) {
      return {
        id: generateId(),
        sessionId,
        type: 'artificial_rhythm',
        score: 20,
        confidence: Math.min(0.5 + (1 - cv) * 0.5, 0.95),
        timestamp: new Date(),
        evidence: [
          `CV=${cv.toFixed(3)} — unusually regular access pattern`,
          `${events.length} accesses with avg interval ${avg.toFixed(0)}ms`
        ],
        details: { cv, avgInterval: avg, count: events.length, stdDev }
      };
    }

    return null;
  }

  private detectMemoryOnlyOps(
    events: FileAccessEvent[], sessionId: string
  ): AntiEvasionSignal | null {
    const reads = events.filter(e => e.operation === 'read');
    if (reads.length < 200) return null;

    const writes = events.filter(e => e.operation === 'write' || e.operation === 'create');
    const readWriteRatio = reads.length / Math.max(writes.length, 1);
    if (readWriteRatio <= 20) return null;

    // Require evidence of sensitive target access (git objects, secrets, etc.)
    // to avoid flagging benign read-only tools like grep/cat on source code.
    const sensitivePaths = ['.git/objects', '.git/logs', '.git/config', '.env',
      'secrets', 'credentials', 'id_rsa', 'id_ed25519', '.pem', '.pfx', '.ssh'];
    const sensitiveReads = reads.filter(e =>
      sensitivePaths.some(p => e.filePath.toLowerCase().includes(p))
    );
    if (sensitiveReads.length < 3 && reads.length < 500) return null;

    const uniqueFiles = new Set(reads.map(e => e.filePath.split(/[/\\]/).pop() || ''));
    const gitFiles = [...uniqueFiles].filter(f => f.startsWith('.git') || f.includes('objects'));
    const hasGitContent = gitFiles.length > 0;

    const confidence = sensitiveReads.length >= 10 ? 0.8 : hasGitContent ? 0.75 : 0.65;

    return {
      id: generateId(),
      sessionId,
      type: 'memory_only_ops',
      score: 25,
      confidence,
      timestamp: new Date(),
      evidence: [
        `${reads.length} reads vs ${writes.length} writes (ratio ${readWriteRatio.toFixed(1)})`,
        hasGitContent ? 'Git objects read without local write' : 'Mass reads without local writes',
        sensitiveReads.length > 0 ? `${sensitiveReads.length} sensitive target reads` : ''
      ].filter(Boolean),
      details: { reads: reads.length, writes: writes.length, ratio: readWriteRatio, hasGitContent, sensitiveTargets: sensitiveReads.length }
    };
  }

  private detectNoTempFiles(
    events: FileAccessEvent[], sessionId: string
  ): AntiEvasionSignal | null {
    const tempDirs = ['/tmp/', '\\temp\\', '/temp/', '\\tmp\\', 'C:\\Windows\\Temp', '/var/tmp/'];
    const tempAccesses = events.filter(e =>
      tempDirs.some(d => e.filePath.toLowerCase().includes(d.toLowerCase()))
    );
    if (tempAccesses.length > 0) return null;

    const reads = events.filter(e => e.operation === 'read');
    if (reads.length < 300) return null;

    return {
      id: generateId(),
      sessionId,
      type: 'no_temp_files',
      score: 15,
      confidence: 0.6,
      timestamp: new Date(),
      evidence: [
        `${reads.length} reads with zero temp file writes`,
        'Sustained read operation without OS temp file usage'
      ],
      details: { reads: reads.length }
    };
  }

  private detectProcessChain(
    processes: ProcessEvent[], sessionId: string
  ): AntiEvasionSignal | null {
    if (processes.length < 3) return null;

    const chainStarts: string[] = [];
    const knownAiProcesses = ['cursor', 'copilot', 'claude', 'codex', 'gemini', 'grok', 'windsurf', 'aider'];

    for (const proc of processes) {
      const nameLower = proc.name.toLowerCase();
      if (knownAiProcesses.some(a => nameLower.includes(a))) {
        chainStarts.push(proc.name);
      }
    }

    if (chainStarts.length === 0) return null;

    const downstreamTools = processes.filter(p => {
      const cmdLower = p.commandLine.toLowerCase();
      return cmdLower.includes('curl') || cmdLower.includes('wget') ||
             cmdLower.includes('python') || cmdLower.includes('node') ||
             cmdLower.includes('git') || cmdLower.includes('powershell') ||
             cmdLower.includes('bash');
    });

    if (downstreamTools.length >= 2) {
      return {
        id: generateId(),
        sessionId,
        type: 'process_chain',
        score: 35,
        confidence: Math.min(0.5 + downstreamTools.length * 0.05, 0.9),
        timestamp: new Date(),
        evidence: [
          `AI agent (${chainStarts.join(', ')}) → ${downstreamTools.length} downstream tools`,
          `Tools: ${downstreamTools.map(t => t.name).join(', ')}`
        ],
        details: { aiAgents: chainStarts, downstream: downstreamTools.length, tools: downstreamTools.map(t => t.name) }
      };
    }

    return null;
  }

  private detectPreparationPhase(
    processes: ProcessEvent[], sessionId: string
  ): AntiEvasionSignal | null {
    const prepCommands = [
      'git cat-file', 'git rev-list', 'git ls-tree',
      'git pack-objects', 'git count-objects', 'git diff --cached',
      'git stash', 'git bundle list-heads'
    ];

    const found: ProcessEvent[] = [];
    for (const proc of processes) {
      const cmdLower = proc.commandLine.toLowerCase();
      if (prepCommands.some(c => cmdLower.includes(c))) {
        found.push(proc);
      }
    }

    if (found.length > 0) {
      const uniqueCmds = [...new Set(found.map(p => {
        for (const c of prepCommands) {
          if (p.commandLine.toLowerCase().includes(c)) return c;
        }
        return p.commandLine;
      }))];

      return {
        id: generateId(),
        sessionId,
        type: 'preparation_phase',
        score: 30,
        confidence: Math.min(0.5 + found.length * 0.1, 0.95),
        timestamp: new Date(),
        evidence: [
          `Preparation commands: ${uniqueCmds.join(', ')}`,
          `${found.length} commands executed — possible snapshot preparation`
        ],
        details: { commands: uniqueCmds, count: found.length }
      };
    }

    return null;
  }

  private detectDistributedChain(
    flows: NetworkFlow[], sessionId: string
  ): AntiEvasionSignal | null {
    const activeUploadFlows = flows.filter(f => f.bytesSent > 1024 * 1024);
    const dests = new Set(activeUploadFlows.map(f => f.hostname ?? f.destAddr));

    if (dests.size >= 3) {
      const destList = [...dests].sort();
      return {
        id: generateId(),
        sessionId,
        type: 'distributed_chain',
        score: 45,
        confidence: 0.9,
        timestamp: new Date(),
        evidence: [
          `Distributed exfiltration pattern: uploads (>1MB) to ${dests.size} distinct hosts: ${destList.join(', ')}`,
          'Indicates possible parallel/split data exfiltration evasion technique'
        ],
        details: { hosts: destList, count: dests.size }
      };
    }
    return null;
  }
}
