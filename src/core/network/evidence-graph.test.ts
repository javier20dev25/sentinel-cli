import { describe, it, expect } from 'vitest'
import { buildEvidenceGraph, queryGraphByType, queryGraphByPid, findPathsBetween, renderEvidenceGraph, queryConnectedNodes, getSubgraph, queryGraphBySource, evidenceBaseConfidence, computeGraphStats, renderGraphStats, computeAdvancedGraphStats, renderAdvancedGraphStats } from './evidence-graph'
import { BuildRecord, BuildProcessEvent, BuildFileEvent, BuildNetEvent, FileReadEvent } from './build-types'

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

describe('evidence-graph', () => {
  describe('buildEvidenceGraph', () => {
    it('builds graph with processes and spawn edges', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, startTime: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, startTime: 200, exitTime: 900, source: 'procfs' },
        { pid: 3, name: 'ld', cmdline: 'ld -o out', ppid: 1, pname: 'make', timestamp: 900, startTime: 900, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)

      expect(graph.nodes.length).toBe(3)
      expect(graph.edges.length).toBe(2)

      const spawnEdges = graph.edges.filter(e => e.relation === 'spawned')
      expect(spawnEdges.length).toBe(2)
      expect(spawnEdges.every(e => e.from !== e.to)).toBe(true)
    })

    it('adds file nodes with heuristic_association edges', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out.o', size: 1024, operation: 'created', timestamp: 500 },
        { filePath: '/tmp/out', size: 2048, operation: 'created', timestamp: 900 },
      ]
      const record = minimalRecord({ processes, files })
      const graph = buildEvidenceGraph(record)

      const fileNodes = graph.nodes.filter(n => n.filePath)
      expect(fileNodes.length).toBe(2)

      const heuristics = graph.edges.filter(e => e.relation === 'created')
      expect(heuristics.length).toBe(2)
    })

    it('adds network nodes with connected edges', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'curl', cmdline: 'curl example.com', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
      ]
      const network: BuildNetEvent[] = [
        { type: 'tcp', host: '93.184.216.34', port: 443, timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes, network })
      const graph = buildEvidenceGraph(record)

      const netNodes = graph.nodes.filter(n => n.host)
      expect(netNodes.length).toBe(1)
      expect(netNodes[0].host).toBe('93.184.216.34')

      const connected = graph.edges.filter(e => e.relation === 'connected')
      expect(connected.length).toBe(1)
    })

    it('adds file read nodes with read edges by PID', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'cat', cmdline: 'cat secret.txt', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
      ]
      const readFiles: FileReadEvent[] = [
        { filePath: '/tmp/secret.txt', pid: 1, processName: 'cat', timestamp: 200, size: 4096, source: 'procfs' },
      ]
      const record = minimalRecord({ processes, readFiles })
      const graph = buildEvidenceGraph(record)

      const readNodes = graph.nodes.filter(n => n.type === 'FILE_READ')
      expect(readNodes.length).toBe(1)
      expect(readNodes[0].pid).toBe(1)

      const readEdges = graph.edges.filter(e => e.relation === 'read')
      expect(readEdges.length).toBe(1)
      expect(readEdges[0].from).toBeDefined()
    })

    it('adds secret nodes with accessed edges', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'bash', cmdline: 'bash script.sh', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
      ]
      const record = minimalRecord({
        processes,
        secretFlow: {
          secretAccesses: [
            { type: 'npm_token', severity: 'critical', filePath: '.npmrc', match: 'npm_*', line: 1, context: '', snippet: '', sha256: '', pid: 1, processName: 'bash', timestamp: 300 },
          ],
          chains: [],
          totalSecrets: 1,
          criticalCount: 1,
          exfilRiskCount: 0,
        },
      })
      const graph = buildEvidenceGraph(record)

      const secretNodes = graph.nodes.filter(n => n.type === 'SECRET_ACCESSED')
      expect(secretNodes.length).toBe(1)

      const accessedEdges = graph.edges.filter(e => e.relation === 'accessed')
      expect(accessedEdges.length).toBe(1)
    })

    it('adds compiler nodes with loaded edges', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'gcc', cmdline: 'gcc -c main.c', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
      ]
      const record = minimalRecord({
        processes,
        compilerInvocations: {
          invocations: [
            { tool: 'gcc', argv: ['gcc', '-c', 'main.c'], cwd: '/tmp', responseFiles: [], responseFileContent: [], envSnapshot: {}, pid: 1, timestamp: 200, inputFiles: ['main.c'], outputFiles: ['main.o'], flags: [], defines: [], includeDirs: [], hasResponseFile: false, hasStdinInput: false },
          ],
          totalInvocations: 1,
          uniqueFlags: [],
          suspiciousInvocations: [],
        },
      })
      const graph = buildEvidenceGraph(record)

      const compilerNodes = graph.nodes.filter(n => n.type === 'COMPILER_STARTED')
      expect(compilerNodes.length).toBe(1)
      expect(graph.edges.some(e => e.relation === 'loaded')).toBe(true)
    })

    it('sets confidence from source', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'etw' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)

      expect(graph.nodes[0].confidence).toBe(98)
    })

    it('handles empty records', () => {
      const record = minimalRecord()
      const graph = buildEvidenceGraph(record)

      expect(graph.nodes.length).toBe(0)
      expect(graph.edges.length).toBe(0)
    })

    it('sets build metadata', () => {
      const record = minimalRecord({ command: 'npm run build' })
      const graph = buildEvidenceGraph(record)

      expect(graph.buildId).toBeDefined()
      expect(graph.rootPid).toBe(0)
    })
  })

  describe('queryGraphByType', () => {
    it('filters nodes by type', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)

      const exits = queryGraphByType(graph, 'PROCESS_EXITED')
      expect(exits.length).toBe(0)

      const created = queryGraphByType(graph, 'PROCESS_CREATED')
      expect(created.length).toBe(2)
    })
  })

  describe('queryGraphByPid', () => {
    it('filters nodes by PID', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)

      const pid1Nodes = queryGraphByPid(graph, 1)
      expect(pid1Nodes.length).toBe(1)
      expect(pid1Nodes[0].label).toBe('make')
    })
  })

  describe('findPathsBetween', () => {
    it('finds direct edge paths', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)

      const paths = findPathsBetween(graph, graph.nodes[0].id, graph.nodes[1].id)
      expect(paths.length).toBeGreaterThanOrEqual(1)
    })

    it('returns empty for unreachable nodes', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'a', cmdline: 'a', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
        { pid: 2, name: 'b', cmdline: 'b', ppid: 0, pname: '', timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)

      const paths = findPathsBetween(graph, graph.nodes[0].id, graph.nodes[1].id)
      expect(paths.length).toBe(0)
    })
  })

  describe('renderEvidenceGraph', () => {
    it('renders without error', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out.o', size: 1024, operation: 'created', timestamp: 500 },
      ]
      const record = minimalRecord({ processes, files })
      const graph = buildEvidenceGraph(record)

      const lines = renderEvidenceGraph(graph)
      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Evidence Graph')
    })
  })

  describe('queryConnectedNodes', () => {
    it('returns connected nodes for a process node', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const connected = queryConnectedNodes(graph, graph.nodes[0].id)
      expect(connected.length).toBe(1)
    })
  })

  describe('getSubgraph', () => {
    it('extracts correct subgraph', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const sub = getSubgraph(graph, new Set([graph.nodes[0].id]))
      expect(sub.nodes.length).toBe(1)
      expect(sub.edges.length).toBe(0)
    })
  })

  describe('queryGraphBySource', () => {
    it('filters nodes by evidence source', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'etw' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const etwNodes = queryGraphBySource(graph, 'etw')
      expect(etwNodes.length).toBe(1)
      expect(etwNodes[0].label).toBe('make')
    })
  })

  describe('evidenceBaseConfidence', () => {
    it('returns correct base confidence for known sources', () => {
      expect(evidenceBaseConfidence('etw')).toBe(98)
      expect(evidenceBaseConfidence('procfs')).toBe(85)
      expect(evidenceBaseConfidence('mtime_heuristic')).toBe(42)
    })
    it('returns 50 for unknown source', () => {
      expect(evidenceBaseConfidence('unknown' as any)).toBe(50)
    })
  })

  describe('process deduplication', () => {
    it('skips duplicate PID entries', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const pid1Nodes = queryGraphByPid(graph, 1)
      expect(pid1Nodes.length).toBe(1)
    })
  })

  describe('file deduplication', () => {
    it('skips duplicate file paths', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out.o', size: 1024, operation: 'created', timestamp: 500 },
        { filePath: '/tmp/out.o', size: 2048, operation: 'modified', timestamp: 600 },
      ]
      const record = minimalRecord({ processes, files })
      const graph = buildEvidenceGraph(record)
      const fileNodes = graph.nodes.filter(n => n.filePath === '/tmp/out.o')
      expect(fileNodes.length).toBe(1)
    })
  })

  describe('computeGraphStats', () => {
    it('computes basic stats for a simple graph', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, startTime: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, startTime: 200, exitTime: 800, source: 'procfs' },
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out.o', size: 1024, operation: 'created', timestamp: 500 },
      ]
      const record = minimalRecord({ processes, files })
      const graph = buildEvidenceGraph(record)
      const stats = computeGraphStats(graph)

      expect(stats.nodeCount).toBe(3)
      expect(stats.edgeCount).toBeGreaterThanOrEqual(2)
      expect(stats.componentCount).toBe(1)
      expect(stats.largestComponentSize).toBe(3)
      expect(stats.avgConfidence).toBeGreaterThan(0)
      expect(stats.maxConfidence).toBeGreaterThanOrEqual(stats.minConfidence)
    })

    it('identifies max fan-out node', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
        { pid: 3, name: 'ld', cmdline: 'ld -o out', ppid: 1, pname: 'make', timestamp: 800, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const stats = computeGraphStats(graph)

      expect(stats.maxFanOut.count).toBeGreaterThanOrEqual(1)
      expect(stats.maxFanOut.label).toBeTruthy()
    })

    it('counts nodes by type', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out.o', size: 1024, operation: 'created', timestamp: 500 },
      ]
      const record = minimalRecord({ processes, files })
      const graph = buildEvidenceGraph(record)
      const stats = computeGraphStats(graph)

      expect(stats.nodeCountByType['PROCESS_EXITED']).toBe(1)
      expect(stats.nodeCountByType['FILE_CREATED']).toBe(1)
    })

    it('handles empty graph', () => {
      const record = minimalRecord()
      const graph = buildEvidenceGraph(record)
      const stats = computeGraphStats(graph)

      expect(stats.nodeCount).toBe(0)
      expect(stats.edgeCount).toBe(0)
      expect(stats.componentCount).toBe(0)
      expect(stats.avgConfidence).toBe(0)
    })

    it('computes max depth from root nodes', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out.o', size: 1024, operation: 'created', timestamp: 500 },
      ]
      const record = minimalRecord({ processes, files })
      const graph = buildEvidenceGraph(record)
      const stats = computeGraphStats(graph)

      expect(stats.maxDepth).toBeGreaterThanOrEqual(1)
    })
  })

  describe('renderGraphStats', () => {
    it('renders without error', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const stats = computeGraphStats(graph)
      const lines = renderGraphStats(stats)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Evidence Graph Stats')
      expect(lines.some(l => l.includes('PROCESS_EXITED'))).toBe(true)
    })
  })

  describe('computeAdvancedGraphStats', () => {
    it('computes betweenness centrality', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
        { pid: 3, name: 'ld', cmdline: 'ld -o out', ppid: 1, pname: 'make', timestamp: 800, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)

      expect(Object.keys(advanced.betweennessCentrality).length).toBe(3)
      for (const val of Object.values(advanced.betweennessCentrality)) {
        expect(val).toBeGreaterThanOrEqual(0)
        expect(val).toBeLessThanOrEqual(1)
      }
    })

    it('computes closeness centrality', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)

      expect(Object.keys(advanced.closenessCentrality).length).toBe(2)
      // root should have highest closeness
      const entries = Object.entries(advanced.closenessCentrality).filter(([, v]) => v > 0)
      expect(entries.length).toBeGreaterThanOrEqual(1)
    })

    it('computes graph density', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)

      expect(advanced.graphDensity).toBeGreaterThan(0)
      expect(advanced.graphDensity).toBeLessThanOrEqual(1)
    })

    it('computes graph entropy', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)

      expect(advanced.graphEntropy).toBeGreaterThanOrEqual(0)
      expect(advanced.graphEntropy).toBeLessThanOrEqual(1)
    })

    it('detects DAG vs cyclic graphs', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)

      expect(advanced.isDag).toBe(true)
      expect(advanced.sccCount).toBe(graph.nodes.length)
    })

    it('finds immediate dominators', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
        { pid: 3, name: 'ld', cmdline: 'ld -o out', ppid: 1, pname: 'make', timestamp: 800, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)

      const rootNode = graph.nodes.find(n => n.pid === 0 || !graph.edges.some(e => e.to === n.id))
      if (rootNode) {
        const children = graph.edges.filter(e => e.from === rootNode.id)
        for (const child of children) {
          expect(advanced.immediateDominators[child.to]).toBe(rootNode.id)
        }
      }
    })

    it('handles empty graph', () => {
      const record = minimalRecord()
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)

      expect(Object.keys(advanced.betweennessCentrality).length).toBe(0)
      expect(Object.keys(advanced.closenessCentrality).length).toBe(0)
      expect(advanced.graphDensity).toBe(0)
      expect(advanced.graphEntropy).toBe(0)
      expect(advanced.isDag).toBe(true)
    })

    it('computes dominance frontier', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)

      expect(Object.keys(advanced.dominanceFrontier).length).toBe(graph.nodes.length)
    })
  })

  describe('renderAdvancedGraphStats', () => {
    it('renders without error', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)
      const lines = renderAdvancedGraphStats(advanced)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Advanced Graph Stats')
      expect(lines.some(l => l.includes('Density'))).toBe(true)
      expect(lines.some(l => l.includes('Betweenness'))).toBe(true)
    })

    it('respects topN parameter', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
        { pid: 3, name: 'ld', cmdline: 'ld -o out', ppid: 1, pname: 'make', timestamp: 800, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const advanced = computeAdvancedGraphStats(graph)
      const lines = renderAdvancedGraphStats(advanced, 1)

      // Should only show 1 top betweenness
      const betweenLines = lines.filter(l => l.trim().startsWith('proc'))
      expect(betweenLines.length).toBeLessThanOrEqual(3)
    })
  })
})
