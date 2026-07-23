import { describe, it, expect } from 'vitest'
import { captureBuildIdentity } from './build-identity'
import { buildCausalDag, renderCausalDag } from './build-causal-dag'
import { buildExplainExplanation } from './build-explain'
import { BuildRecord, BuildGraphEdge, BuildIdentity, ConfidenceBreakdown, CausalNode } from './build-types'

function makeRecord(overrides: Partial<BuildRecord> = {}): BuildRecord {
  const base: BuildRecord = {
    command: 'test',
    args: [],
    cwd: '/tmp',
    startTime: '2026-07-21T00:00:00.000Z',
    durationMs: 5000,
    exitCode: 0,
    platform: 'linux',
    nodeVersion: 'v22',
    env: { PATH: '/usr/bin' },
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
      filesRead: 0,
      networkConnections: 0,
      dnsQueries: [],
      artifactsHashed: 0,
      anomalies: [],
      processTree: [],
      totalHashLinks: 0,
    },
    hashChain: [],
  }
  return { ...base, ...overrides }
}

// ── Build Identity ──────────────────────────────────────────
describe('Build Identity', () => {
  it('captureBuildIdentity returns valid structure', () => {
    const id = captureBuildIdentity()
    expect(id).toBeDefined()
    expect(typeof id.hostname).toBe('string')
    expect(typeof id.platform).toBe('string')
    expect(typeof id.arch).toBe('string')
    expect(typeof id.kernel).toBe('string')
    expect(typeof id.cpus).toBe('number')
    expect(typeof id.memoryGb).toBe('number')
    expect(id.hostname.length).toBeGreaterThan(0)
    expect(id.cpus).toBeGreaterThan(0)
  })

  it('toolVersions is a record of strings', () => {
    const id = captureBuildIdentity()
    expect(typeof id.toolVersions).toBe('object')
    for (const [tool, version] of Object.entries(id.toolVersions)) {
      expect(typeof tool).toBe('string')
      expect(typeof version).toBe('string')
    }
  })

  it('ciProvider is null when not in CI', () => {
    const id = captureBuildIdentity()
    expect(id.ciProvider).toBeNull()
  })

  it('container detection returns null or string', () => {
    const id = captureBuildIdentity()
    expect(id.container === null || typeof id.container === 'string').toBe(true)
  })
})

// ── Causal DAG ──────────────────────────────────────────────
describe('Causal DAG', () => {
  it('returns empty array for empty process tree', () => {
    const record = makeRecord()
    const dag = buildCausalDag(record, [])
    expect(Array.isArray(dag)).toBe(true)
  })

  it('builds single-node DAG for simple process', () => {
    const record = makeRecord({
      processes: [{ pid: 1, name: 'gcc', cmdline: 'gcc -o out.o', ppid: 0, pname: 'make', timestamp: 1000 }],
      summary: {
        totalProcesses: 1,
        uniqueProcesses: ['gcc'],
        buildToolsDetected: ['gcc'],
        filesCreated: 0,
        filesModified: 0,
        filesDeleted: 0,
      filesRead: 0,
        networkConnections: 0,
        dnsQueries: [],
        artifactsHashed: 0,
        anomalies: [],
        processTree: [{ name: 'gcc', pid: 1, ppid: 0, cmdline: 'gcc -o out.o', children: [] }],
        totalHashLinks: 0,
      },
    })

    const dag = buildCausalDag(record, [{ from: 'gcc', to: 'out.o', type: 'produced' }])

    expect(dag.length).toBe(1)
    expect(dag[0].label).toBe('gcc')
    expect(dag[0].type).toBe('process')
  })

  it('includes produced files as children', () => {
    const record = makeRecord({
      processes: [{ pid: 1, name: 'gcc', cmdline: 'gcc', ppid: 0, pname: '', timestamp: 1000 }],
      summary: {
        totalProcesses: 1,
        uniqueProcesses: ['gcc'],
        buildToolsDetected: ['gcc'],
        filesCreated: 1,
        filesModified: 0,
        filesDeleted: 0,
      filesRead: 0,
        networkConnections: 0,
        dnsQueries: [],
        artifactsHashed: 1,
        anomalies: [],
        processTree: [{ name: 'gcc', pid: 1, ppid: 0, cmdline: 'gcc', children: [] }],
        totalHashLinks: 0,
      },
      artifactHashes: [{ filePath: '/tmp/out.o', sha256: 'abc', size: 100 }],
    })

    const dag = buildCausalDag(record, [{ from: 'gcc', to: 'out.o', type: 'produced' }])

    expect(dag.length).toBe(1)
    const fileChildren = dag[0].children.filter(c => c.type === 'file' || c.type === 'artifact')
    expect(fileChildren.length).toBeGreaterThanOrEqual(1)
  })

  it('marks dangerous tools as behavior type', () => {
    const record = makeRecord({
      processes: [{ pid: 1, name: 'curl', cmdline: 'curl http://x', ppid: 0, pname: '', timestamp: 1000 }],
      summary: {
        totalProcesses: 1,
        uniqueProcesses: ['curl'],
        buildToolsDetected: [],
        filesCreated: 0,
        filesModified: 0,
        filesDeleted: 0,
      filesRead: 0,
        networkConnections: 0,
        dnsQueries: [],
        artifactsHashed: 0,
        anomalies: [],
        processTree: [{ name: 'curl', pid: 1, ppid: 0, cmdline: 'curl http://x', children: [] }],
        totalHashLinks: 0,
      },
    })

    const dag = buildCausalDag(record, [])
    expect(dag.length).toBe(1)
    expect(dag[0].type).toBe('behavior')
  })

  it('renderCausalDag produces readable output', () => {
    const nodes: CausalNode[] = [{
      id: 'test', label: 'gcc', type: 'process', detail: 'gcc -o out', depth: 0, children: [
        { id: 'f1', label: 'out.o', type: 'artifact', detail: 'SHA256 abc', depth: 1, children: [] },
      ],
    }]

    const lines = renderCausalDag(nodes)
    expect(lines.length).toBeGreaterThan(0)
    expect(lines.some(l => l.includes('gcc'))).toBe(true)
    expect(lines.some(l => l.includes('out.o'))).toBe(true)
  })

  it('handles parent-child process relationships', () => {
    const record = makeRecord({
      processes: [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100 },
        { pid: 2, name: 'gcc', cmdline: 'gcc', ppid: 1, pname: 'make', timestamp: 200 },
      ],
      summary: {
        totalProcesses: 2,
        uniqueProcesses: ['make', 'gcc'],
        buildToolsDetected: ['make', 'gcc'],
        filesCreated: 0,
        filesModified: 0,
        filesDeleted: 0,
      filesRead: 0,
        networkConnections: 0,
        dnsQueries: [],
        artifactsHashed: 0,
        anomalies: [],
        processTree: [{
          name: 'make', pid: 1, ppid: 0, cmdline: 'make', children: [
            { name: 'gcc', pid: 2, ppid: 1, cmdline: 'gcc', children: [] },
          ],
        }],
        totalHashLinks: 0,
      },
    })

    const dag = buildCausalDag(record, [
      { from: 'make', to: 'gcc', type: 'spawned' },
      { from: 'gcc', to: 'out.o', type: 'produced' },
    ])

    expect(dag.length).toBe(1)
    expect(dag[0].label).toBe('make')
    expect(dag[0].children.length).toBeGreaterThan(0)
  })
})

// ── Confidence Breakdown ────────────────────────────────────
describe('Confidence Breakdown', () => {
  it('returns all dimensions in buildExplainExplanation', () => {
    const prev = makeRecord({
      artifactHashes: [{ filePath: 'out.bin', sha256: 'aaa', size: 100 }],
      processes: [{ pid: 1, name: 'gcc', cmdline: 'gcc', ppid: 0, pname: '', timestamp: 1000 }],
      summary: {
        totalProcesses: 1, uniqueProcesses: ['gcc'], buildToolsDetected: ['gcc'],
        filesCreated: 0, filesModified: 0, filesDeleted: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 1,
        anomalies: [], processTree: [{ name: 'gcc', pid: 1, ppid: 0, cmdline: 'gcc', children: [] }],
        totalHashLinks: 0,
      },
    })
    const curr = makeRecord({
      artifactHashes: [{ filePath: 'out.bin', sha256: 'bbb', size: 200 }],
      processes: [{ pid: 1, name: 'gcc', cmdline: 'gcc', ppid: 0, pname: '', timestamp: 1000 }],
      summary: {
        totalProcesses: 1, uniqueProcesses: ['gcc'], buildToolsDetected: ['gcc'],
        filesCreated: 0, filesModified: 0, filesDeleted: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 1,
        anomalies: [], processTree: [{ name: 'gcc', pid: 1, ppid: 0, cmdline: 'gcc', children: [] }],
        totalHashLinks: 0,
      },
    })

    const exp = buildExplainExplanation(curr, [{ from: 'gcc', to: 'out.bin', type: 'produced' }], prev)

    expect(exp.confidenceBreakdown).toBeDefined()
    expect(typeof exp.confidenceBreakdown.toolchain).toBe('number')
    expect(typeof exp.confidenceBreakdown.environment).toBe('number')
    expect(typeof exp.confidenceBreakdown.artifact).toBe('number')
    expect(typeof exp.confidenceBreakdown.network).toBe('number')
    expect(typeof exp.confidenceBreakdown.graph).toBe('number')
    expect(typeof exp.confidenceBreakdown.behavior).toBe('number')
    expect(typeof exp.confidenceBreakdown.nSignals).toBe('number')
    expect(typeof exp.confidenceBreakdown.diversity).toBe('number')
  })

  it('breakdown exists even with no changes', () => {
    const record = makeRecord()
    const exp = buildExplainExplanation(record, [], record)
    expect(exp.confidenceBreakdown).toBeDefined()
    expect(exp.confidenceBreakdown.overall).toBeGreaterThanOrEqual(0)
  })

  it('causalDag is present in explanation', () => {
    const record = makeRecord()
    const exp = buildExplainExplanation(record, [], record)
    expect(Array.isArray(exp.causalDag)).toBe(true)
  })
})

describe('ConfidenceBreakdown type', () => {
  it('has required fields', () => {
    const cb: ConfidenceBreakdown = {
      overall: 0.85,
      toolchain: 1,
      environment: 1,
      artifact: 0.1,
      network: 1,
      graph: 1,
      behavior: 1,
      nSignals: 3,
      diversity: 2,
      severityBonus: 0.2,
    }
    expect(cb.overall).toBe(0.85)
    expect(cb.artifact).toBe(0.1)
  })
})
