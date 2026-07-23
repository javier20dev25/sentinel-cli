import { describe, it, expect } from 'vitest'
import { compactRecord, SERIALIZATION_LIMITS } from './build-serializer'
import { BuildRecord } from './build-types'

function makeBigRecord(): BuildRecord {
  const processes = Array.from({ length: 1000 }, (_, i) => ({
    pid: i, name: `proc-${i}`, cmdline: `cmd-${i}`.repeat(200),
    ppid: i > 0 ? i - 1 : 0, pname: i > 0 ? `proc-${i - 1}` : '',
    timestamp: Date.now(), startTime: Date.now(), exitTime: Date.now() + 100,
    source: 'polling' as const,
  }))
  const files = Array.from({ length: 3000 }, (_, i) => ({
    filePath: `/tmp/file-${i}.o`, size: 1024, operation: 'created' as const,
    timestamp: Date.now(),
  }))
  const network = Array.from({ length: 500 }, (_, i) => ({
    type: 'tcp' as const, host: `host-${i}.com`, port: 80 + i,
    timestamp: Date.now(),
  }))
  return {
    command: 'make', args: [], cwd: '/tmp',
    startTime: new Date().toISOString(), durationMs: 1000, exitCode: 0,
    platform: 'linux', nodeVersion: 'v20',
    env: {}, processes, files, network,
    artifactHashes: [],
    summary: {
      totalProcesses: processes.length,
      uniqueProcesses: processes.map(p => p.name),
      buildToolsDetected: [],
      filesCreated: files.length, filesModified: 0, filesDeleted: 0,
      filesRead: 0, networkConnections: network.length,
      dnsQueries: [], artifactsHashed: 0,
      anomalies: Array.from({ length: 300 }, (_, i) => `anomaly-${i}`),
      processTree: [], totalHashLinks: 0,
    },
    hashChain: [],
  }
}

describe('build-serializer', () => {
  describe('compactRecord', () => {
    it('trims large process arrays', () => {
      const record = makeBigRecord()
      const compacted = compactRecord(record)
      expect(compacted.processes.length).toBeLessThanOrEqual(SERIALIZATION_LIMITS.maxProcesses)
      expect(compacted.processes.length).toBe(SERIALIZATION_LIMITS.maxProcesses)
    })

    it('trims large file arrays', () => {
      const record = makeBigRecord()
      const compacted = compactRecord(record)
      expect(compacted.files.length).toBeLessThanOrEqual(SERIALIZATION_LIMITS.maxFiles)
    })

    it('trims large anomaly arrays', () => {
      const record = makeBigRecord()
      const compacted = compactRecord(record)
      expect(compacted.summary.anomalies.length).toBeLessThanOrEqual(200)
    })

    it('trims long cmdline strings', () => {
      const record = makeBigRecord()
      const compacted = compactRecord(record)
      for (const p of compacted.processes) {
        expect(p.cmdline.length).toBeLessThanOrEqual(SERIALIZATION_LIMITS.maxStringLength + 3)
      }
    })

    it('preserves small records unchanged', () => {
      const record: BuildRecord = {
        command: 'echo', args: ['hello'], cwd: '/tmp',
        startTime: new Date().toISOString(), durationMs: 10, exitCode: 0,
        platform: 'linux', nodeVersion: 'v20',
        env: {}, processes: [], files: [], network: [],
        artifactHashes: [],
        summary: {
          totalProcesses: 0, uniqueProcesses: [], buildToolsDetected: [],
          filesCreated: 0, filesModified: 0, filesDeleted: 0,
          filesRead: 0, networkConnections: 0, dnsQueries: [],
          artifactsHashed: 0, anomalies: [], processTree: [], totalHashLinks: 0,
        },
        hashChain: [],
      }
      const compacted = compactRecord(record)
      expect(compacted.processes.length).toBe(0)
      expect(compacted.summary.anomalies.length).toBe(0)
    })
  })
})
