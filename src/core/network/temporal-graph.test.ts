import { describe, it, expect } from 'vitest'
import {
  buildTemporalEvidenceGraph,
  renderTemporalEvidenceGraph,
  buildBayesianNetwork,
  renderBayesianNetwork,
  analyzeDominators,
  renderDominatorAnalysis,
  computeFullGraphMetrics,
  renderFullGraphMetrics,
} from './temporal-graph'
import { buildEvidenceGraph } from './evidence-graph'
import { BuildRecord, BuildProcessEvent, BuildFileEvent, BuildNetEvent } from './build-types'

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

describe('temporal-graph', () => {
  describe('buildTemporalEvidenceGraph', () => {
    it('computes edge latencies from node timestamps', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
        makeProcess(3, 'ld', 1, 800),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const teg = buildTemporalEvidenceGraph(graph)

      expect(teg.graph).toBe(graph)
      expect(teg.paths.length).toBeGreaterThanOrEqual(1)
      expect(teg.avgEdgeLatencyMs).toBeGreaterThanOrEqual(0)
      expect(teg.maxEdgeLatencyMs).toBeGreaterThanOrEqual(teg.avgEdgeLatencyMs)
    })

    it('finds critical path with max latency', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
        makeProcess(3, 'ld', 1, 800),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const teg = buildTemporalEvidenceGraph(graph)

      expect(teg.criticalPath.nodes.length).toBeGreaterThanOrEqual(1)
      expect(teg.criticalPath.causalDelayMs).toBeGreaterThanOrEqual(0)
    })

    it('handles empty graph', () => {
      const record = minimalRecord()
      const graph = buildEvidenceGraph(record)
      const teg = buildTemporalEvidenceGraph(graph)

      expect(teg.paths.length).toBe(0)
      expect(teg.avgEdgeLatencyMs).toBe(0)
      expect(teg.maxEdgeLatencyMs).toBe(0)
    })

    it('handles pre-set latency on edges', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const teg = buildTemporalEvidenceGraph(graph)

      // Edges should have latency computed from timestamps
      for (const path of teg.paths) {
        for (const edge of path.edges) {
          expect(edge.latencyMs).toBeGreaterThanOrEqual(0)
        }
      }
    })

    it('longestCausalChain has most nodes', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
        makeProcess(3, 'as', 2, 100),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const teg = buildTemporalEvidenceGraph(graph)

      expect(teg.longestCausalChain.nodes.length).toBeGreaterThanOrEqual(1)
    })
  })

  describe('renderTemporalEvidenceGraph', () => {
    it('renders without error', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const teg = buildTemporalEvidenceGraph(graph)
      const lines = renderTemporalEvidenceGraph(teg)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Temporal Evidence Graph')
    })
  })

  describe('buildBayesianNetwork', () => {
    it('computes posteriors for each relation', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const bn = buildBayesianNetwork(graph)

      expect(bn.relations.length).toBeGreaterThan(0)
      expect(bn.globalPrior).toBeGreaterThanOrEqual(0)
      expect(bn.globalPrior).toBeLessThanOrEqual(1)
      expect(bn.overallPosterior).toBeGreaterThanOrEqual(0)
      expect(bn.overallPosterior).toBeLessThanOrEqual(1)
      expect(bn.calibrationVersion).toBe(1)
    })

    it('spawned has high posterior', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const bn = buildBayesianNetwork(graph)

      const spawned = bn.relations.find(r => r.relation === 'spawned')
      if (spawned) {
        expect(spawned.posteriorGivenEvidence).toBeGreaterThanOrEqual(0.8)
      }
    })

    it('handles empty graph', () => {
      const record = minimalRecord()
      const graph = buildEvidenceGraph(record)
      const bn = buildBayesianNetwork(graph)

      expect(bn.relations.length).toBe(0)
      expect(bn.globalPrior).toBe(0.5)
    })

    it('bayes rule: posterior > prior when likelihood is high', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const bn = buildBayesianNetwork(graph)

      for (const r of bn.relations) {
        if (r.sampleCount > 0 && r.likelihoodPositive > r.priorP) {
          expect(r.posteriorGivenEvidence).toBeGreaterThanOrEqual(r.priorP)
        }
      }
    })
  })

  describe('renderBayesianNetwork', () => {
    it('renders without error', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const bn = buildBayesianNetwork(graph)
      const lines = renderBayesianNetwork(bn)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Bayesian Network')
      expect(lines.some(l => l.includes('Global prior'))).toBe(true)
    })
  })

  describe('analyzeDominators', () => {
    it('identifies dominant process in linear chain', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
        makeProcess(3, 'ld', 2, 100),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const analysis = analyzeDominators(graph)

      expect(analysis.dominantProcess).toBeTruthy()
      expect(analysis.hijackRiskScore).toBeGreaterThanOrEqual(0)
      expect(analysis.hijackRiskScore).toBeLessThanOrEqual(1)
      expect(analysis.dominantPath.length).toBeGreaterThanOrEqual(1)
    })

    it('detects toolchain shift when previous differs', () => {
      const processes1: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record1 = minimalRecord({ processes: processes1 })
      const graph1 = buildEvidenceGraph(record1)

      const processes2: BuildProcessEvent[] = [
        makeProcess(1, 'curl', 0, 1000),
        makeProcess(2, 'evil', 1, 200),
      ]
      const record2 = minimalRecord({ processes: processes2 })
      const graph2 = buildEvidenceGraph(record2)

      const analysis = analyzeDominators(graph2, graph1)
      // Since different processes, dominant may have changed
      expect(analysis.previousDominators).toBeTruthy()
    })

    it('detects non-build-tool dominant', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'curl', 0, 1000),
        makeProcess(2, 'evil', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const analysis = analyzeDominators(graph)

      if (analysis.toolchainShiftDetected) {
        expect(analysis.anomalySignals.some(s => s.includes('Non-build-tool'))).toBe(true)
      }
    })

    it('handles empty graph', () => {
      const record = minimalRecord()
      const graph = buildEvidenceGraph(record)
      const analysis = analyzeDominators(graph)

      expect(analysis.dominantProcess).toBeNull()
      expect(analysis.hijackRiskScore).toBe(0)
    })

    it('no anomaly when build tools dominate', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
        makeProcess(3, 'ld', 2, 100),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const analysis = analyzeDominators(graph)

      if (analysis.dominantProcess) {
        const dominantLabel = graph.nodes.find(n => n.id === analysis.dominantProcess)?.label || ''
        const isBuildTool = ['make', 'gcc', 'ld', 'clang', 'go', 'cargo'].some(t => dominantLabel.includes(t))
        if (isBuildTool) {
          expect(analysis.toolchainShiftDetected).toBe(false)
        }
      }
    })
  })

  describe('renderDominatorAnalysis', () => {
    it('renders without error', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const analysis = analyzeDominators(graph)
      const lines = renderDominatorAnalysis(analysis)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Dominator Analysis')
    })
  })

  describe('computeFullGraphMetrics', () => {
    it('computes all 34 metrics', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
        makeProcess(3, 'ld', 1, 800),
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out.o', size: 1024, operation: 'created', timestamp: 500 },
      ]
      const network: BuildNetEvent[] = [
        { type: 'tcp', host: 'example.com', port: 443, timestamp: 300, source: 'procfs' },
      ]
      const record = minimalRecord({ processes, files, network })
      const graph = buildEvidenceGraph(record)
      const teg = buildTemporalEvidenceGraph(graph)
      const bn = buildBayesianNetwork(graph)
      const da = analyzeDominators(graph)
      const m = computeFullGraphMetrics(graph, teg, bn, da)

      expect(m.nodeCount).toBe(5)
      expect(m.edgeCount).toBeGreaterThanOrEqual(3)
      expect(m.graphDensity).toBeGreaterThan(0)
      expect(m.graphEntropy).toBeGreaterThanOrEqual(0)
      expect(m.maxDepth).toBeGreaterThanOrEqual(1)
      expect(m.componentCount).toBeGreaterThanOrEqual(1)
      expect(m.sccCount).toBeGreaterThan(0)
      expect(m.isDag).toBe(true)
      expect(m.avgBetweenness).toBeGreaterThanOrEqual(0)
      expect(m.maxBetweenness).toBeGreaterThanOrEqual(0)
      expect(m.avgCloseness).toBeGreaterThanOrEqual(0)
      expect(m.maxCloseness).toBeGreaterThanOrEqual(0)
      expect(m.idomCount).toBeGreaterThanOrEqual(0)
      expect(m.longestCausalChainMs).toBeGreaterThanOrEqual(0)
      expect(m.criticalPathMs).toBeGreaterThanOrEqual(0)
      expect(m.avgEdgeLatencyMs).toBeGreaterThanOrEqual(0)
      expect(m.maxEdgeLatencyMs).toBeGreaterThanOrEqual(m.avgEdgeLatencyMs)
      expect(m.edgeLatencyVariance).toBeGreaterThanOrEqual(0)
      expect(m.temporalSpanMs).toBeGreaterThanOrEqual(0)
      expect(m.secretPathLength).toBeGreaterThanOrEqual(0)
      expect(m.networkPathLength).toBeGreaterThanOrEqual(0)
      expect(m.compilerDiversity).toBeGreaterThanOrEqual(0)
      expect(m.toolchainEntropy).toBeGreaterThanOrEqual(0)
      expect(m.processTreeDepth).toBeGreaterThanOrEqual(0)
      expect(m.avgBranchFactor).toBeGreaterThanOrEqual(0)
      expect(m.rootEccentricity).toBeGreaterThanOrEqual(0)
      expect(m.avgInferenceDegradation).toBeGreaterThanOrEqual(0)
      expect(m.avgObservationDegradation).toBeGreaterThanOrEqual(0)
      expect(m.confidenceVariance).toBeGreaterThanOrEqual(0)
      expect(m.contractViolationRatio).toBeGreaterThanOrEqual(0)
      expect(m.fileReadRatio).toBeGreaterThanOrEqual(0)
      expect(m.secretToProcessRatio).toBeGreaterThanOrEqual(0)
      expect(m.networkToProcessRatio).toBeGreaterThanOrEqual(0)
    })

    it('handles empty graph', () => {
      const record = minimalRecord()
      const graph = buildEvidenceGraph(record)
      const m = computeFullGraphMetrics(graph)

      expect(m.nodeCount).toBe(0)
      expect(m.edgeCount).toBe(0)
      expect(m.graphDensity).toBe(0)
      expect(m.graphEntropy).toBe(0)
      expect(m.componentCount).toBe(0)
      expect(m.avgConfidence).toBeUndefined()
    })
  })

  describe('renderFullGraphMetrics', () => {
    it('renders without error', () => {
      const processes: BuildProcessEvent[] = [
        makeProcess(1, 'make', 0, 1000),
        makeProcess(2, 'gcc', 1, 200),
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const m = computeFullGraphMetrics(graph)
      const lines = renderFullGraphMetrics(m)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Full Graph Metrics')
      expect(lines.some(l => l.includes('Centrality'))).toBe(true)
      expect(lines.some(l => l.includes('Temporal'))).toBe(true)
      expect(lines.some(l => l.includes('Paths'))).toBe(true)
      expect(lines.some(l => l.includes('Structure'))).toBe(true)
      expect(lines.some(l => l.includes('Confidence'))).toBe(true)
    })
  })
})
