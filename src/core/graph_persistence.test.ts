import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { AgencyGraph } from './agency_graph';
import { saveGraphSnapshot, loadGraphHistory, computeGraphTrend } from './graph_persistence';

const TEST_REPO_PATH = path.resolve('test-repo-hash');
const TEST_REPO_HASH = crypto.createHash('sha256').update(TEST_REPO_PATH).digest('hex').substring(0, 12);
const TEST_DIR = path.join(os.homedir(), '.sentinel', 'graphs', TEST_REPO_HASH);

function makeMockGraph(overrides?: Partial<AgencyGraph>): AgencyGraph {
  return {
    nodes: [
      { id: 'n1', subcode: 'WF-004', title: 'test', severity: 'CRITICAL', riskScore: 85, contribution: 50, file: 'test.yml', line: 10, category: 'workflow' },
    ],
    edges: [],
    chains: [
      {
        nodes: [
          { id: 'n1', subcode: 'WF-004', title: 'test', severity: 'CRITICAL', riskScore: 85, contribution: 50, file: 'test.yml', line: 10, category: 'workflow' },
        ],
        score: 85,
        confidence: 0.9,
      },
    ],
    ...overrides,
  };
}

describe('graph_persistence', () => {
  beforeEach(() => {
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    }
  });

  it('saves and loads a graph snapshot (round-trip)', () => {
    const graph = makeMockGraph();
    const repoPath = 'test-repo-hash';
    const savedPath = saveGraphSnapshot(repoPath, graph);
    expect(fs.existsSync(savedPath)).toBe(true);

    const loaded = loadGraphHistory(repoPath);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].nodes).toBe(1);
    expect(loaded[0].edges).toBe(0);
    expect(loaded[0].chains).toBe(1);
    expect(loaded[0].fullGraph.nodes).toHaveLength(1);
    expect(loaded[0].fullGraph.nodes[0].subcode).toBe('WF-004');
  });

  it('computeGraphTrend returns deltas with two snapshots', () => {
    const repoPath = 'test-repo-hash';

    saveGraphSnapshot(repoPath, makeMockGraph({
      chains: [{ nodes: [{ id: 'n1', subcode: 'WF-004', title: 'test', severity: 'CRITICAL', riskScore: 50, contribution: 25, file: 'test.yml', line: 10, category: 'workflow' }], score: 50, confidence: 0.8 }],
    }));

    saveGraphSnapshot(repoPath, makeMockGraph({
      chains: [{ nodes: [{ id: 'n1', subcode: 'WF-004', title: 'test', severity: 'CRITICAL', riskScore: 85, contribution: 50, file: 'test.yml', line: 10, category: 'workflow' }], score: 85, confidence: 0.9 }],
    }));

    const trend = computeGraphTrend(repoPath);
    expect(trend.chainCountDelta).toBe(0);
    expect(trend.scoreDelta).toBe(35);
  });

  it('auto-prunes to keep only last 30 snapshots', () => {
    const repoPath = 'test-repo-hash';

    for (let i = 0; i < 35; i++) {
      saveGraphSnapshot(repoPath, makeMockGraph());
    }

    const loaded = loadGraphHistory(repoPath);
    expect(loaded.length).toBeLessThanOrEqual(30);
  });
});
