import { describe, it, expect } from 'vitest'
import {
  computeGraphDiff,
  renderGraphDiff,
  ContinuousLearner,
  renderContinuousLearner,
  generateCausalNarrative,
  renderCausalNarrative,
} from './graph-analytics'
import { buildEvidenceGraph } from './evidence-graph'
import { BuildRecord, BuildProcessEvent } from './build-types'

function minimalRecord(overrides?: Partial<BuildRecord>): BuildRecord {
  return {
    command: 'test',
    args: [],
    cwd: '/tmp',
    startTime: new Date().toISOString(),
    durationMs: 1000,
    exitCode: 0,
    platform: 'linux',
    nodeVersion: 'v20',
    env: {},
    processes: [],
    files: [],
    network: [],
    artifactHashes: [],
    summary: {
      totalProcesses: 0,
      uniqueProcesses: [],
      buildToolsDetected: [],
      filesCreated: 0,
      filesModified: 0,
      filesDeleted: 0,
      filesRead: 0,
      networkConnections: 0,
      dnsQueries: [],
      artifactsHashed: 0,
      anomalies: [],
      processTree: [],
      totalHashLinks: 0,
    },
    hashChain: [],
    ...overrides,
  }
}

function makeProcess(pid: number, name: string, ppid: number, ts: number): BuildProcessEvent {
  return { pid, name, cmdline: name, ppid, pname: '', timestamp: ts, startTime: ts, exitTime: ts + 500, source: 'procfs' }
}

describe('graph-analytics', () => {
  describe('computeGraphDiff', () => {
    it('detects added nodes between two graphs', () => {
      const record1 = minimalRecord({
        processes: [makeProcess(1, 'make', 0, 1000)],
      })
      const record2 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
        ],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)

      expect(diff.nodesAdded.length).toBeGreaterThanOrEqual(1)
      expect(diff.totalNodeDelta).toBeGreaterThan(0)
      expect(diff.riskScore).toBeGreaterThanOrEqual(0)
    })

    it('detects removed nodes', () => {
      const record1 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
        ],
      })
      const record2 = minimalRecord({
        processes: [makeProcess(1, 'make', 0, 1000)],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)

      expect(diff.nodesRemoved.length).toBeGreaterThanOrEqual(1)
      expect(diff.totalNodeDelta).toBeLessThan(0)
    })

    it('detects edge changes', () => {
      const record1 = minimalRecord({
        processes: [makeProcess(1, 'make', 0, 1000)],
      })
      const record2 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
        ],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)

      expect(diff.edgesAdded.length).toBeGreaterThanOrEqual(1)
      expect(diff.totalEdgeDelta).toBeGreaterThan(0)
    })

    it('detects centrality shifts', () => {
      const record1 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
        ],
      })
      const record2 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
          makeProcess(3, 'ld', 2, 100),
          makeProcess(4, 'as', 2, 150),
        ],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)

      expect(diff.graphStatsBefore).toBeDefined()
      expect(diff.graphStatsAfter).toBeDefined()
    })

    it('handles identical structure graphs', () => {
      const record1 = minimalRecord({
        processes: [makeProcess(1, 'make', 0, 1000)],
      })
      const record2 = minimalRecord({
        processes: [makeProcess(1, 'make', 0, 1000)],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)

      // Same structure: same node count, edge count
      expect(diff.nodesAdded.length).toBe(graphA.nodes.length)
      expect(diff.nodesRemoved.length).toBe(graphB.nodes.length)
      expect(diff.edgesAdded.length).toBe(graphA.edges.length)
      expect(diff.edgesRemoved.length).toBe(graphB.edges.length)
    })

    it('detects dominator changes', () => {
      const record1 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
        ],
      })
      const record2 = minimalRecord({
        processes: [
          makeProcess(1, 'curl', 0, 1000),
          makeProcess(2, 'evil', 1, 200),
        ],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)

      expect(diff.dominatorChanges).toBeDefined()
    })

    it('detects critical path changes', () => {
      const record1 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
        ],
      })
      const record2 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
          makeProcess(3, 'ld', 2, 100),
        ],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)

      expect(diff.criticalPathBefore).toBeDefined()
      expect(diff.criticalPathAfter).toBeDefined()
    })

    it('computes Bayesian shift', () => {
      const record1 = minimalRecord({
        processes: [makeProcess(1, 'make', 0, 1000)],
      })
      const record2 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
          makeProcess(3, 'ld', 1, 800),
        ],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)

      expect(diff.bayesianShift).toBeDefined()
      expect(Array.isArray(diff.bayesianShift)).toBe(true)
    })
  })

  describe('renderGraphDiff', () => {
    it('renders without error', () => {
      const record1 = minimalRecord({
        processes: [makeProcess(1, 'make', 0, 1000)],
      })
      const record2 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
        ],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)
      const lines = renderGraphDiff(diff)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Graph Diff')
      expect(lines.some(l => l.includes('Risk score'))).toBe(true)
    })

    it('shows anomaly signals when present', () => {
      const record1 = minimalRecord({
        processes: [makeProcess(1, 'make', 0, 1000)],
      })
      const record2 = minimalRecord({
        processes: [
          makeProcess(1, 'make', 0, 1000),
          makeProcess(2, 'gcc', 1, 200),
        ],
      })
      const graphA = buildEvidenceGraph(record1)
      const graphB = buildEvidenceGraph(record2)
      const diff = computeGraphDiff(graphA, graphB)
      const lines = renderGraphDiff(diff)

      expect(lines.some(l => l.includes('Anomaly signals'))).toBe(true)
    })
  })

  describe('ContinuousLearner', () => {
    it('records feedback entries', () => {
      const learner = new ContinuousLearner()
      learner.recordFeedback('build-1', 'normal', 'normal', 0.95)
      learner.recordFeedback('build-2', 'malicious', 'malicious', 0.88)

      const stats = learner.getFeedbackStats()
      expect(stats.total).toBe(2)
      expect(stats.correct).toBe(2)
      expect(stats.accuracy).toBe(1)
    })

    it('tracks incorrect predictions', () => {
      const learner = new ContinuousLearner()
      learner.recordFeedback('build-1', 'normal', 'malicious', 0.6)

      const stats = learner.getFeedbackStats()
      expect(stats.total).toBe(1)
      expect(stats.incorrect).toBe(1)
      expect(stats.accuracy).toBe(0)
    })

    it('groups feedback by predicted label', () => {
      const learner = new ContinuousLearner()
      learner.recordFeedback('b1', 'normal', 'normal', 0.9)
      learner.recordFeedback('b2', 'normal', 'malicious', 0.7)
      learner.recordFeedback('b3', 'malicious', 'malicious', 0.8)

      const stats = learner.getFeedbackStats()
      expect(stats.byPredictedLabel.normal.total).toBe(2)
      expect(stats.byPredictedLabel.normal.correct).toBe(1)
      expect(stats.byPredictedLabel.malicious.total).toBe(1)
      expect(stats.byPredictedLabel.malicious.correct).toBe(1)
    })

    it('registers model versions', () => {
      const learner = new ContinuousLearner()
      learner.promoteModel('v1.0', 0.85, 0.90, { w1: 0.5 }, 0.1, ['f1'], 100)

      const latest = learner.getLatestModel()
      expect(latest).toBeTruthy()
      expect(latest!.version).toBe('v1.0')
      expect(latest!.accuracy).toBe(0.85)
      expect(latest!.trainedOnExamples).toBe(100)
    })

    it('tracks version history', () => {
      const learner = new ContinuousLearner()
      learner.promoteModel('v1.0', 0.80, 0.85, {}, 0, [], 100)
      learner.promoteModel('v1.1', 0.85, 0.90, {}, 0, [], 200)

      const history = learner.getVersionHistory()
      expect(history.length).toBe(2)
      expect(history[0].version).toBe('v1.0')
      expect(history[1].version).toBe('v1.1')
    })

    it('rolls back to previous version', () => {
      const learner = new ContinuousLearner()
      learner.promoteModel('v1.0', 0.80, 0.85, {}, 0, [], 100)
      learner.promoteModel('v1.1', 0.60, 0.65, {}, 0, [], 200)

      const rolledBack = learner.rollback('v1.0')
      expect(rolledBack).toBeTruthy()
      expect(rolledBack!.version).toBe('v1.0')
      expect(learner.getLatestModel()!.version).toBe('v1.0')
    })

    it('detects when retraining is needed', () => {
      const learner = new ContinuousLearner()

      // No feedback yet
      expect(learner.shouldRetrain()).toBe(false)

      // Add enough feedback with low accuracy
      for (let i = 0; i < 25; i++) {
        learner.recordFeedback(`b${i}`, 'normal', 'malicious', 0.5)
      }

      // Register a good model first
      learner.promoteModel('v1.0', 0.9, 0.95, {}, 0, [], 100)

      // Now accuracy dropped significantly
      expect(learner.shouldRetrain()).toBe(true)
    })

    it('computes accuracy for last N entries', () => {
      const learner = new ContinuousLearner()
      learner.recordFeedback('b1', 'normal', 'normal', 0.9)
      learner.recordFeedback('b2', 'normal', 'malicious', 0.7)
      learner.recordFeedback('b3', 'malicious', 'malicious', 0.8)

      expect(learner.getAccuracyLastN(2)).toBe(0.5)
      expect(learner.getAccuracyLastN(3)).toBe(2 / 3)
      expect(learner.getAccuracyLastN(0)).toBe(0)
    })
  })

  describe('renderContinuousLearner', () => {
    it('renders without error', () => {
      const learner = new ContinuousLearner()
      learner.recordFeedback('b1', 'normal', 'normal', 0.9)
      learner.promoteModel('v1.0', 0.85, 0.90, {}, 0, [], 100)

      const lines = renderContinuousLearner(learner)
      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Continuous Learning Pipeline')
      expect(lines.some(l => l.includes('v1.0'))).toBe(true)
    })

    it('shows retrain warning when needed', () => {
      const learner = new ContinuousLearner()
      for (let i = 0; i < 25; i++) {
        learner.recordFeedback(`b${i}`, 'normal', 'malicious', 0.5)
      }
      learner.promoteModel('v1.0', 0.9, 0.95, {}, 0, [], 100)

      const lines = renderContinuousLearner(learner)
      expect(lines.some(l => l.includes('RETRAIN'))).toBe(true)
    })
  })

  describe('generateCausalNarrative', () => {
    it('generates narrative from a simple build', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const narrative = generateCausalNarrative(graph)

      expect(narrative.title).toBeTruthy()
      expect(narrative.summary).toBeTruthy()
      expect(narrative.events.length).toBeGreaterThan(0)
      expect(narrative.timeline.length).toBeGreaterThan(0)
      expect(narrative.riskAssessment).toBeTruthy()
      expect(Array.isArray(narrative.keyFindings)).toBe(true)
      expect(Array.isArray(narrative.recommendations)).toBe(true)
    })

    it('detects critical events in narrative', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'curl', 0, 1000),
      ]
      const record = minimalRecord({
        processes,
      })
      const graph = buildEvidenceGraph(record)
      const narrative = generateCausalNarrative(graph)

      // Narrative should have events and a risk assessment
      expect(narrative.events.length).toBeGreaterThan(0)
      expect(narrative.riskAssessment).toBeTruthy()
      expect(narrative.timeline.length).toBeGreaterThan(0)
    })

    it('generates timeline with severity icons', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const narrative = generateCausalNarrative(graph)

      expect(narrative.timeline.some(t => t.includes('🟢') || t.includes('🟡') || t.includes('🔴'))).toBe(true)
    })
  })

  describe('renderCausalNarrative', () => {
    it('renders without error', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const narrative = generateCausalNarrative(graph)
      const lines = renderCausalNarrative(narrative)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines.some(l => l.includes('Timeline'))).toBe(true)
      expect(lines.some(l => l.includes('Risk Assessment'))).toBe(true)
      expect(lines.some(l => l.includes('Key Findings'))).toBe(true)
      expect(lines.some(l => l.includes('Recommendations'))).toBe(true)
    })
  })
})
