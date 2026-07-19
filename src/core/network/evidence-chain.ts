'use strict';

import {
  NetworkFlow, FileAccessEvent, ProcessEvent, GitCommandEvent,
  EvidenceChain, EvidenceChainStep, Behavior, BehaviorType, generateId
} from './types';

const MAX_CHAIN_WINDOW_MS = 300000;

export class EvidenceChainCorrelator {
  private chains: EvidenceChain[] = [];

  getChains(): EvidenceChain[] {
    return this.chains;
  }

  getChainNames(): string[] {
    return this.chains.map(c => c.name);
  }

  correlate(
    flows: NetworkFlow[],
    processes: ProcessEvent[],
    fileAccesses: FileAccessEvent[],
    gitCommands: GitCommandEvent[],
    behaviors: Behavior[],
    sessionId: string
  ): EvidenceChain[] {
    const newChains: EvidenceChain[] = [];

    const exfilChain = this.buildExfiltrationChain(flows, processes, fileAccesses, gitCommands, behaviors, sessionId);
    if (exfilChain) newChains.push(exfilChain);

    const prepChain = this.buildPreparationChain(gitCommands, processes, behaviors, sessionId);
    if (prepChain) newChains.push(prepChain);

    const snapChain = this.buildSnapshotChain(fileAccesses, flows, behaviors, sessionId);
    if (snapChain) newChains.push(snapChain);

    const embedChain = this.buildEmbeddingChain(fileAccesses, behaviors, sessionId);
    if (embedChain) newChains.push(embedChain);

    this.chains.push(...newChains);
    return newChains;
  }

  private buildExfiltrationChain(
    flows: NetworkFlow[], processes: ProcessEvent[],
    fileAccesses: FileAccessEvent[], gitCommands: GitCommandEvent[],
    behaviors: Behavior[], sessionId: string
  ): EvidenceChain | null {
    const hasGitRead = behaviors.some(b =>
      b.type === 'git_objects_read' || b.type === 'git_history_read' || b.type === 'repo_indexed'
    );
    const hasMassRead = behaviors.some(b => b.type === 'mass_file_read');
    const hasBundleOrArchive = behaviors.some(b =>
      b.type === 'git_bundle_created' || b.type === 'git_archive_created'
    );
    const hasUpload = behaviors.some(b =>
      b.type === 'code_upload' || b.type === 'git_bundle_uploaded'
    );
    const hasSuspiciousConn = flows.some(f =>
      f.bytesSent > 1024 * 1024 &&
      f.destAddr !== '127.0.0.1'
    );

    if ((!hasGitRead && !hasMassRead) || !hasUpload) return null;

    const steps: EvidenceChainStep[] = [];
    let order = 0;

    if (hasGitRead || hasMassRead) {
      const ev = behaviors.find(b => b.type === 'git_objects_read' || b.type === 'mass_file_read' || b.type === 'git_history_read');
      steps.push({
        order: order++,
        type: 'repo_read',
        description: ev ? ev.evidence[0] : 'Repository files accessed',
        timestamp: ev ? ev.timestamp : new Date(),
        eventIds: ev ? [ev.id] : [],
      });
    }

    if (hasBundleOrArchive) {
      const bb = behaviors.find(b => b.type === 'git_bundle_created' || b.type === 'git_archive_created');
      steps.push({
        order: order++,
        type: 'compression',
        description: bb ? bb.evidence[0] : 'Repository compressed into bundle/archive',
        timestamp: bb ? bb.timestamp : new Date(),
        eventIds: bb ? [bb.id] : [],
      });
    }

    if (hasSuspiciousConn) {
      const connFlow = flows.filter(f => f.bytesSent > 1024 * 1024)
        .sort((a, b) => b.bytesSent - a.bytesSent)[0];
      steps.push({
        order: order++,
        type: 'connection_open',
        description: connFlow
          ? `Connection to ${connFlow.hostname || connFlow.destAddr}:${connFlow.destPort}`
          : 'Suspicious connection established',
        timestamp: connFlow ? connFlow.timestamp : new Date(),
        eventIds: connFlow ? [connFlow.id] : [],
      });
    }

    if (hasUpload) {
      const up = behaviors.find(b => b.type === 'code_upload' || b.type === 'git_bundle_uploaded');
      steps.push({
        order: order++,
        type: 'data_transmit',
        description: up ? up.evidence[0] : 'Data transmitted to external host',
        timestamp: up ? up.timestamp : new Date(),
        eventIds: up ? [up.id] : [],
      });
    }

    const sortedSteps = [...steps].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    sortedSteps.forEach((s, i) => s.order = i);

    const timeSpan = sortedSteps.length > 1
      ? sortedSteps[sortedSteps.length - 1].timestamp.getTime() - sortedSteps[0].timestamp.getTime()
      : 0;

    if (sortedSteps.length < 2) return null;

    return {
      id: generateId(),
      sessionId,
      name: 'repository_exfiltration_chain',
      confidence: Math.min(0.5 + sortedSteps.length * 0.1 + (timeSpan < 60000 ? 0.2 : 0), 0.95),
      steps: sortedSteps,
      timestamp: new Date(),
      summary: `Exfiltration chain: ${sortedSteps.length} phases over ${(timeSpan / 1000).toFixed(0)}s — ` +
               sortedSteps.map(s => s.type.replace(/_/g, ' ')).join(' → ')
    };
  }

  private buildPreparationChain(
    gitCommands: GitCommandEvent[], processes: ProcessEvent[],
    behaviors: Behavior[], sessionId: string
  ): EvidenceChain | null {
    const prepCommands = ['rev-list', 'pack-objects', 'cat-file', 'ls-tree'];
    const found = gitCommands.filter(g => prepCommands.includes(g.action));
    if (found.length < 2) return null;

    const hasBundle = behaviors.some(b => b.type === 'git_bundle_created');
    const hasUpload = behaviors.some(b => b.type === 'code_upload' || b.type === 'git_bundle_uploaded');

    const steps: EvidenceChainStep[] = [];
    let order = 0;

    for (const cmd of found.slice(0, 5)) {
      steps.push({
        order: order++,
        type: 'git_preparation',
        description: cmd.commandLine.substring(0, 120),
        timestamp: cmd.timestamp,
        eventIds: [],
      });
    }

    if (hasBundle) {
      const bb = behaviors.find(b => b.type === 'git_bundle_created');
      steps.push({
        order: order++,
        type: 'archival',
        description: bb ? bb.evidence[0] : 'Bundle created after preparation',
        timestamp: bb ? bb.timestamp : new Date(),
        eventIds: bb ? [bb.id] : [],
      });
    }

    if (hasUpload) {
      const up = behaviors.find(b => b.type === 'code_upload' || b.type === 'git_bundle_uploaded');
      steps.push({
        order: order++,
        type: 'transmission',
        description: up ? up.evidence[0] : 'Data sent after preparation',
        timestamp: up ? up.timestamp : new Date(),
        eventIds: up ? [up.id] : [],
      });
    }

    const sortedSteps = [...steps].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    sortedSteps.forEach((s, i) => s.order = i);

    return {
      id: generateId(),
      sessionId,
      name: 'pre_operational_snapshot',
      confidence: hasUpload ? 0.9 : 0.7,
      steps: sortedSteps,
      timestamp: new Date(),
      summary: `Pre-operational snapshot: ${found.length} git enumeration commands followed by ${hasUpload ? 'exfiltration' : hasBundle ? 'archival' : 'no clear output'}`
    };
  }

  private buildSnapshotChain(
    fileAccesses: FileAccessEvent[], flows: NetworkFlow[],
    behaviors: Behavior[], sessionId: string
  ): EvidenceChain | null {
    const massReadBehaviors = behaviors.filter(b => b.type === 'mass_file_read');
    if (massReadBehaviors.length === 0) return null;
    const hasUpload = behaviors.some(b => b.type === 'code_upload');
    const hasConn = flows.some(f => f.bytesSent > 100 * 1024);
    if (!hasUpload && !hasConn) return null;

    const steps: EvidenceChainStep[] = [];
    let order = 0;

    steps.push({
      order: order++,
      type: 'mass_read',
      description: `${fileAccesses.length} files read`,
      timestamp: fileAccesses[0]?.timestamp || new Date(),
      eventIds: massReadBehaviors.map(b => b.id),
    });

    steps.push({
      order: order++,
      type: 'external_transmission',
      description: `${flows.filter(f => f.bytesSent > 0).length} external flows, ${(flows.reduce((s, f) => s + f.bytesSent, 0) / 1024 / 1024).toFixed(1)}MB total`,
      timestamp: flows[flows.length - 1]?.timestamp || new Date(),
      eventIds: [],
    });

    return {
      id: generateId(),
      sessionId,
      name: 'full_snapshot_transfer',
      confidence: 0.75,
      steps,
      timestamp: new Date(),
      summary: `Snapshot transfer: ${fileAccesses.length} files read → external transmission`
    };
  }

  private buildEmbeddingChain(
    fileAccesses: FileAccessEvent[], behaviors: Behavior[],
    sessionId: string
  ): EvidenceChain | null {
    const embeddingBehaviors = behaviors.filter(b => b.type === 'embeddings_generated');
    if (embeddingBehaviors.length === 0) return null;
    const hasAiConn = behaviors.some(b => b.type === 'suspicious_connection' || b.type === 'ai_prompt_sent');
    if (!hasAiConn && fileAccesses.length < 100) return null;

    const steps: EvidenceChainStep[] = [];
    let order = 0;

    steps.push({
      order: order++,
      type: 'embedding_generation',
      description: `${fileAccesses.length} files analyzed for embedding`,
      timestamp: embeddingBehaviors[0].timestamp,
      eventIds: embeddingBehaviors.map(b => b.id),
    });

    const aiFlow = behaviors.find(b => b.type === 'suspicious_connection' || b.type === 'ai_prompt_sent');
    if (aiFlow) {
      steps.push({
        order: order++,
        type: 'ai_transmission',
        description: aiFlow.evidence[0],
        timestamp: aiFlow.timestamp,
        eventIds: [aiFlow.id],
      });
    }

    return {
      id: generateId(),
      sessionId,
      name: 'ai_embedding_chain',
      confidence: 0.7,
      steps,
      timestamp: new Date(),
      summary: `AI embedding pipeline: file analysis → AI API transmission`
    };
  }

  reset(): void {
    this.chains = [];
  }
}
