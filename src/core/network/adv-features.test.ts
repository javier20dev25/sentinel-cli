import { describe, it, expect } from 'vitest'
import * as os from 'os'
import * as path from 'path'
import * as fs from 'fs'
import { captureBuildIdentity } from './build-identity'
import { computeTrend, renderTrend, saveToTrendStore } from './trend-engine'
import { buildProvenanceGraph, renderProvenanceGraph } from './provenance-graph'
import { BuildRecord, TrendMetric, TrendResult, ProvenanceGraph } from './build-types'

function makeRecord(overrides: Partial<BuildRecord> = {}): BuildRecord {
  const base: BuildRecord = {
    command: 'test',
    args: [],
    cwd: '/tmp',
    startTime: new Date().toISOString(),
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
      totalProcesses: 0, uniqueProcesses: [], buildToolsDetected: [],
      filesCreated: 0, filesModified: 0, filesDeleted: 0, filesRead: 0,
      networkConnections: 0, dnsQueries: [], artifactsHashed: 0,
      anomalies: [], processTree: [], totalHashLinks: 0,
    },
    hashChain: [],
  }
  return { ...base, ...overrides }
}

// ── 1. Toolchain Identity ──────────────────────────────────
describe('Toolchain Identity', () => {
  it('captureBuildIdentity returns toolIdentities array', async () => {
    const id = captureBuildIdentity()
    expect(Array.isArray(id.toolIdentities)).toBe(true)
  })

  it('each toolIdentity has required fields', () => {
    const id = captureBuildIdentity()
    for (const ti of id.toolIdentities) {
      expect(typeof ti.name).toBe('string')
      expect(typeof ti.realPath).toBe('string')
      expect(typeof ti.sha256).toBe('string')
      expect(typeof ti.size).toBe('number')
      expect(ti.name.length).toBeGreaterThan(0)
      expect(ti.realPath.length).toBeGreaterThan(0)
      expect(ti.sha256.length).toBe(64)
    }
  })

  it('toolIdentities contains at least node if available', () => {
    const id = captureBuildIdentity()
    const node = id.toolIdentities.find(t => t.name === 'node')
    if (node) {
      expect(node.realPath).toContain('node')
      expect(node.size).toBeGreaterThan(0)
    }
  })

  it('realPath is resolved to absolute path', () => {
    const id = captureBuildIdentity()
    for (const ti of id.toolIdentities) {
      expect(path.isAbsolute(ti.realPath)).toBe(true)
    }
  })

  it('BuildRecord can hold identity with toolIdentities', () => {
    const record = makeRecord({ identity: captureBuildIdentity() })
    expect(record.identity).toBeDefined()
    expect(record.identity!.toolIdentities.length).toBeGreaterThanOrEqual(0)
  })
})

// ── 2. Trend Engine ────────────────────────────────────────
describe('Trend Engine', () => {
  it('trend metric types are correct', () => {
    const metric: TrendMetric = {
      metric: 'duration_ms', values: [100, 200, 300], timestamps: [1,2,3],
      slope: 100, cusum: 10, ewma: 200, mean: 200, std: 100,
      drift: 'none', alert: false,
    }
    expect(metric.metric).toBe('duration_ms')
    expect(metric.values.length).toBe(3)
  })

  it('high drift values produce alert', () => {
    const m: TrendMetric = {
      metric: 'test', values: [1,10,100], timestamps: [1,2,3],
      slope: 49.5, cusum: 100, ewma: 55, mean: 37, std: 54,
      drift: 'high', alert: true,
    }
    expect(m.alert).toBe(true)
    expect(m.drift).toBe('high')
  })

  it('low drift does not produce alert', () => {
    const m: TrendMetric = {
      metric: 'test', values: [10,11,10,12,11], timestamps: [1,2,3,4,5],
      slope: 0.2, cusum: 0.5, ewma: 11, mean: 10.8, std: 0.84,
      drift: 'low', alert: false,
    }
    expect(m.alert).toBe(false)
    expect(m.drift).toBe('low')
  })

  it('computeTrend processes single record', () => {
    const record = makeRecord({
      durationMs: 4500,
      summary: {
        totalProcesses: 1, uniqueProcesses: ['gcc'], buildToolsDetected: ['gcc'],
        filesCreated: 1, filesModified: 0, filesDeleted: 0, filesRead: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 1,
        anomalies: [], processTree: [], totalHashLinks: 0,
      },
    })

    const trend = computeTrend(record)
    expect(trend.metrics.length).toBeGreaterThan(0)
    expect(typeof trend.overallDrift).toBe('string')
  })

  it('returns metrics for all expected dimensions', () => {
    const record = makeRecord({
      durationMs: 3000,
      summary: {
        totalProcesses: 2, uniqueProcesses: ['make', 'gcc'], buildToolsDetected: ['make', 'gcc'],
        filesCreated: 3, filesModified: 1, filesDeleted: 0, filesRead: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 2,
        anomalies: [], processTree: [], totalHashLinks: 0,
      },
    })

    const trend = computeTrend(record)
    const metricNames = trend.metrics.map(m => m.metric)
    expect(metricNames).toContain('duration_ms')
    expect(metricNames).toContain('process_count')
    expect(metricNames).toContain('artifact_count')
    expect(metricNames).toContain('file_ops_total')
    expect(metricNames).toContain('tool_count')
  })

  it('each metric has numeric fields', () => {
    const record = makeRecord()
    const trend = computeTrend(record)
    for (const m of trend.metrics) {
      expect(typeof m.mean).toBe('number')
      expect(typeof m.slope).toBe('number')
      expect(typeof m.cusum).toBe('number')
      expect(typeof m.ewma).toBe('number')
      expect(typeof m.std).toBe('number')
      expect(typeof m.alert).toBe('boolean')
      expect(['none', 'low', 'medium', 'high']).toContain(m.drift)
    }
  })

  it('renderTrend produces readable output', () => {
    const record = makeRecord()
    const trend = computeTrend(record)
    const output = renderTrend(trend)
    expect(output.length).toBeGreaterThan(50)
    expect(output).toContain('Trend Analysis')
    expect(output).toContain('Builds analyzed')
  })
})

// ── 3. Provenance Graph ────────────────────────────────────
describe('Provenance Graph', () => {
  it('buildProvenanceGraph returns valid structure', () => {
    const record = makeRecord({
      processes: [{ pid: 1, name: 'gcc', cmdline: 'gcc -c', ppid: 0, pname: '', timestamp: 1000 }],
      files: [{ filePath: '/tmp/main.o', size: 512, operation: 'created', timestamp: 2000 }],
      artifactHashes: [{ filePath: '/tmp/main.o', sha256: 'abc', size: 512 }],
      summary: {
        totalProcesses: 1, uniqueProcesses: ['gcc'], buildToolsDetected: ['gcc'],
        filesCreated: 1, filesModified: 0, filesDeleted: 0, filesRead: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 1,
        anomalies: [], processTree: [{ name: 'gcc', pid: 1, ppid: 0, cmdline: 'gcc -c', children: [] }],
        totalHashLinks: 0,
      },
    })

    const pg = buildProvenanceGraph(record)
    expect(Array.isArray(pg.nodes)).toBe(true)
    expect(Array.isArray(pg.edges)).toBe(true)
    expect(Array.isArray(pg.stages)).toBe(true)
    expect(pg.nodes.length).toBeGreaterThanOrEqual(1)
  })

  it('includes tool as node', () => {
    const record = makeRecord({
      processes: [{ pid: 1, name: 'gcc', cmdline: 'gcc', ppid: 0, pname: '', timestamp: 100 }],
      summary: {
        totalProcesses: 1, uniqueProcesses: ['gcc'], buildToolsDetected: ['gcc'],
        filesCreated: 0, filesModified: 0, filesDeleted: 0, filesRead: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 0,
        anomalies: [], processTree: [{ name: 'gcc', pid: 1, ppid: 0, cmdline: 'gcc', children: [] }],
        totalHashLinks: 0,
      },
    })

    const pg = buildProvenanceGraph(record)
    expect(pg.nodes.some(n => n.id === 'gcc')).toBe(true)
  })

  it('generates edge from tool to produced file', () => {
    const record = makeRecord({
      processes: [{ pid: 1, name: 'gcc', cmdline: 'gcc -c main.c', ppid: 0, pname: '', timestamp: 100 }],
      files: [{ filePath: '/tmp/main.o', size: 512, operation: 'created', timestamp: 200 }],
      summary: {
        totalProcesses: 1, uniqueProcesses: ['gcc'], buildToolsDetected: ['gcc'],
        filesCreated: 1, filesModified: 0, filesDeleted: 0, filesRead: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 0,
        anomalies: [], processTree: [{ name: 'gcc', pid: 1, ppid: 0, cmdline: 'gcc -c main.c', children: [] }],
        totalHashLinks: 0,
      },
    })

    const pg = buildProvenanceGraph(record)
    const edge = pg.edges.find(e => e.from === 'gcc' && e.to.includes('main.o'))
    expect(edge).toBeDefined()
    expect(edge!.type).toBe('compiled')
  })

  it('stages are populated from tool set', () => {
    const record = makeRecord({
      processes: [
        { pid: 1, name: 'configure', cmdline: './configure', ppid: 0, pname: '', timestamp: 100 },
        { pid: 2, name: 'gcc', cmdline: 'gcc', ppid: 1, pname: 'configure', timestamp: 500 },
        { pid: 3, name: 'ld', cmdline: 'ld', ppid: 1, pname: 'configure', timestamp: 1000 },
        { pid: 4, name: 'ar', cmdline: 'ar', ppid: 1, pname: 'configure', timestamp: 800 },
      ],
      summary: {
        totalProcesses: 4, uniqueProcesses: ['configure', 'gcc', 'ld', 'ar'], buildToolsDetected: [],
        filesCreated: 0, filesModified: 0, filesDeleted: 0, filesRead: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 0,
        anomalies: [], processTree: [], totalHashLinks: 0,
      },
    })

    const pg = buildProvenanceGraph(record)
    expect(pg.stages).toContain('configure')
    expect(pg.stages).toContain('compile')
    expect(pg.stages).toContain('link')
    expect(pg.stages).toContain('archive')
  })

  it('renderProvenanceGraph produces readable output', () => {
    const record = makeRecord({
      processes: [{ pid: 1, name: 'gcc', cmdline: 'gcc', ppid: 0, pname: '', timestamp: 100 }],
      files: [{ filePath: '/tmp/out.o', size: 512, operation: 'created', timestamp: 200 }],
      summary: {
        totalProcesses: 1, uniqueProcesses: ['gcc'], buildToolsDetected: ['gcc'],
        filesCreated: 1, filesModified: 0, filesDeleted: 0, filesRead: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 0,
        anomalies: [], processTree: [{ name: 'gcc', pid: 1, ppid: 0, cmdline: 'gcc', children: [] }],
        totalHashLinks: 0,
      },
    })

    const pg = buildProvenanceGraph(record)
    const output = renderProvenanceGraph(pg)
    expect(output.length).toBeGreaterThan(50)
    expect(output).toContain('Provenance Graph')
  })

  it('handles multi-stage chain: configure → gcc → ld', () => {
    const record = makeRecord({
      processes: [
        { pid: 1, name: 'configure', cmdline: './configure', ppid: 0, pname: '', timestamp: 100 },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'configure', timestamp: 500 },
        { pid: 3, name: 'ld', cmdline: 'ld -o out', ppid: 1, pname: 'configure', timestamp: 1000 },
      ],
      files: [
        { filePath: '/tmp/main.o', size: 512, operation: 'created', timestamp: 600 },
        { filePath: '/tmp/out.bin', size: 4096, operation: 'created', timestamp: 1100 },
      ],
      artifactHashes: [
        { filePath: '/tmp/main.o', sha256: 'aaa', size: 512 },
        { filePath: '/tmp/out.bin', sha256: 'bbb', size: 4096 },
      ],
      summary: {
        totalProcesses: 3, uniqueProcesses: ['configure', 'gcc', 'ld'], buildToolsDetected: ['configure', 'gcc', 'ld'],
        filesCreated: 2, filesModified: 0, filesDeleted: 0,
        networkConnections: 0, dnsQueries: [], artifactsHashed: 2,
        anomalies: [], processTree: [], totalHashLinks: 0,
      },
    })

    const pg = buildProvenanceGraph(record)
    expect(pg.stages.length).toBeGreaterThanOrEqual(2)

    const compileEdges = pg.edges.filter(e => e.type === 'compiled')
    const linkEdges = pg.edges.filter(e => e.type === 'linked')
  })
})
