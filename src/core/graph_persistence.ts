import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { AgencyGraph } from './agency_graph';

let _graphSeq = 0;

export interface GraphSnapshot {
  id: string;
  timestamp: string;
  repoHash: string;
  nodes: number;
  edges: number;
  chains: number;
  topChains: Array<{ score: number; confidence: number; nodeCount: number }>;
  fullGraph: AgencyGraph;
}

function getGraphDir(repoPath: string): string {
  const hash = crypto.createHash('sha256').update(path.resolve(repoPath)).digest('hex').substring(0, 12);
  return path.join(os.homedir(), '.sentinel', 'graphs', hash);
}

export function saveGraphSnapshot(repoPath: string, graph: AgencyGraph): string {
  const dir = getGraphDir(repoPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const id = Date.now().toString(36) + '-' + (_graphSeq++).toString(36).padStart(4, '0');
  const hash = crypto.createHash('sha256').update(path.resolve(repoPath)).digest('hex').substring(0, 12);
  const snapshot: GraphSnapshot = {
    id,
    timestamp: new Date().toISOString(),
    repoHash: hash,
    nodes: graph.nodes.length,
    edges: graph.edges.length,
    chains: graph.chains.length,
    topChains: graph.chains.slice(0, 5).map(c => ({
      score: c.score,
      confidence: c.confidence,
      nodeCount: c.nodes.length,
    })),
    fullGraph: graph,
  };

  const safeTimestamp = snapshot.timestamp.replace(/:/g, '-').replace(/\./g, '-');
  const filePath = path.join(dir, `${safeTimestamp}-${id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2));

  autoPrune(dir);

  return filePath;
}

export function loadGraphHistory(repoPath: string): GraphSnapshot[] {
  const dir = getGraphDir(repoPath);
  if (!fs.existsSync(dir)) return [];

  const entries = fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse();

  const snapshots: GraphSnapshot[] = [];
  for (const entry of entries) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(dir, entry), 'utf8'));
      snapshots.push(data as GraphSnapshot);
    } catch {
      // skip corrupt entries
    }
  }
  return snapshots;
}

export function computeGraphTrend(repoPath: string): { chainCountDelta: number; scoreDelta: number } {
  const snapshots = loadGraphHistory(repoPath);
  if (snapshots.length < 2) {
    return { chainCountDelta: 0, scoreDelta: 0 };
  }

  const sorted = [...snapshots].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  const current = sorted[0];
  const previous = sorted[1];

  const currentTopScore = current.topChains[0]?.score ?? 0;
  const previousTopScore = previous.topChains[0]?.score ?? 0;

  return {
    chainCountDelta: current.chains - previous.chains,
    scoreDelta: currentTopScore - previousTopScore,
  };
}

function autoPrune(dir: string): void {
  const entries = fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse();

  if (entries.length <= 30) return;

  const toRemove = entries.slice(30);
  for (const entry of toRemove) {
    try {
      fs.unlinkSync(path.join(dir, entry));
    } catch {
      // ignore
    }
  }
}
