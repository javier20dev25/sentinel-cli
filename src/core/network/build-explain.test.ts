import { describe, it, expect } from 'vitest'
import { buildExplainExplanation, toExplainResult } from './build-explain'
import { BuildRecord, BuildGraphEdge } from './build-types'
import { markRelease, listReleases } from '../../cli/build/release'

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

const emptyGraph: BuildGraphEdge[] = []

describe('buildExplainExplanation', () => {
  it('returns no changes when builds are identical', () => {
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
      artifactHashes: [{ filePath: 'out.o', sha256: 'abc123', size: 100 }],
    })

    const result = buildExplainExplanation(record, emptyGraph, record)

    expect(result.rootCause).toBe('No changes detected')
    expect(result.confidenceLabel).toBe('HIGH')
    expect(result.confidence).toBe(1)
    expect(result.reasons).toHaveLength(0)
  })

  it('detects new artifact hash change', () => {
    const prev = makeRecord({
      artifactHashes: [{ filePath: 'out.bin', sha256: 'aaaa', size: 100 }],
    })
    const curr = makeRecord({
      artifactHashes: [{ filePath: 'out.bin', sha256: 'bbbb', size: 200 }],
    })

    const result = buildExplainExplanation(curr, emptyGraph, prev)

    expect(result.rootCause).not.toBe('')
    expect(result.reasons.length).toBeGreaterThanOrEqual(1)
    expect(result.changes.length).toBeGreaterThanOrEqual(1)
    expect(result.confidence).toBeGreaterThan(0)
  })

  it('detects new process', () => {
    const prev = makeRecord()
    const curr = makeRecord({
      processes: [{ pid: 42, name: 'curl', cmdline: 'curl http://x', ppid: 1, pname: 'make', timestamp: 2000 }],
      durationMs: 10000,
    })

    const result = buildExplainExplanation(curr, emptyGraph, prev)

    expect(result.reasons.some(r => r.includes('curl'))).toBe(true)
    expect(result.changes.some(c => c.includes('curl'))).toBe(true)
  })

  it('detects network connections', () => {
    const prev = makeRecord()
    const curr = makeRecord({
      network: [{ type: 'tcp', host: 'evil.ru', port: 443, timestamp: 3000 }],
    })

    const result = buildExplainExplanation(curr, emptyGraph, prev)

    expect(result.reasons.some(r => r.includes('network') || r.includes('evil'))).toBe(true)
  })

  it('always has a rootCause', () => {
    const prev = makeRecord({
      artifactHashes: [{ filePath: 'a.o', sha256: 'aaa', size: 100 }],
    })
    const curr = makeRecord({
      artifactHashes: [{ filePath: 'b.o', sha256: 'bbb', size: 200 }],
      processes: [{ pid: 2, name: 'gcc', cmdline: 'gcc', ppid: 1, pname: 'make', timestamp: 1000 }],
      durationMs: 10000,
    })

    const result = buildExplainExplanation(curr, emptyGraph, prev)

    expect(result.rootCause).toBeTruthy()
    expect(typeof result.rootCause).toBe('string')
  })

  it('limits reasons to max 5', () => {
    const prev = makeRecord()
    const curr = makeRecord({
      processes: [
        { pid: 1, name: 'proc1', cmdline: 'p1', ppid: 0, pname: '', timestamp: 1000 },
        { pid: 2, name: 'proc2', cmdline: 'p2', ppid: 1, pname: 'proc1', timestamp: 2000 },
        { pid: 3, name: 'proc3', cmdline: 'p3', ppid: 1, pname: 'proc1', timestamp: 3000 },
        { pid: 4, name: 'proc4', cmdline: 'p4', ppid: 1, pname: 'proc1', timestamp: 4000 },
        { pid: 5, name: 'proc5', cmdline: 'p5', ppid: 1, pname: 'proc1', timestamp: 5000 },
        { pid: 6, name: 'proc6', cmdline: 'p6', ppid: 1, pname: 'proc1', timestamp: 6000 },
      ],
      durationMs: 10000,
      artifactHashes: [{ filePath: 'x.o', sha256: 'x', size: 1 }],
      files: [{ filePath: 'f1', size: 1, operation: 'created', timestamp: 1500 }],
      network: [{ type: 'tcp', host: 'example.com', port: 80, timestamp: 7000 }],
    })

    const result = buildExplainExplanation(curr, emptyGraph, prev)

    expect(result.reasons.length).toBeLessThanOrEqual(5)
  })

  it('works without prev (single build)', () => {
    const curr = makeRecord({
      processes: [{ pid: 1, name: 'gcc', cmdline: 'gcc', ppid: 0, pname: '', timestamp: 1000 }],
      durationMs: 5000,
    })

    const result = buildExplainExplanation(curr, emptyGraph)

    expect(result.confidence).toBeGreaterThanOrEqual(0)
    expect(typeof result.rootCause).toBe('string')
  })
})

describe('toExplainResult', () => {
  it('produces valid JSON output', () => {
    const explanation = {
      summary: 'Test',
      confidence: 0.85,
      confidenceLabel: 'HIGH' as const,
      reasons: ['reason 1'],
      changes: ['change 1'],
      rootCause: 'cause',
    }

    const result = toExplainResult('build-123', explanation, 'previous build')

    expect(result.buildId).toBe('build-123')
    expect(result.confidence).toBe(0.85)
    expect(JSON.parse(JSON.stringify(result))).toEqual(result)
  })
})

describe('release module', () => {
  it('markRelease is a function', () => {
    expect(typeof markRelease).toBe('function')
  })

  it('listReleases returns array', () => {
    const releases = listReleases()
    expect(Array.isArray(releases)).toBe(true)
  })
})
