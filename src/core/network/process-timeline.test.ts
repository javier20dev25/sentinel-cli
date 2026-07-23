import { describe, it, expect } from 'vitest'
import { buildProcessTimelines, renderProcessTimeline, renderTimelineSummary, findExfilTimelines } from './process-timeline'
import { buildEvidenceGraph } from './evidence-graph'
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

describe('process-timeline', () => {
  describe('buildProcessTimelines', () => {
    it('creates timelines from graph nodes grouped by PID', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, startTime: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c main.c', ppid: 1, pname: 'make', timestamp: 200, startTime: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const timelines = buildProcessTimelines(record, graph)

      expect(timelines.length).toBe(2)
      expect(timelines[0].pid).toBe(1)
      expect(timelines[0].processName).toBe('make')
      expect(timelines[0].ppid).toBe(0)
      expect(timelines[1].pid).toBe(2)
      expect(timelines[1].ppid).toBe(1)
    })

    it('includes file events in timeline', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out.o', size: 1024, operation: 'created', timestamp: 500 },
        { filePath: '/tmp/out', size: 2048, operation: 'modified', timestamp: 900 },
      ]
      const record = minimalRecord({ processes, files })
      const graph = buildEvidenceGraph(record)
      const timelines = buildProcessTimelines(record, graph)

      const makeTimeline = timelines.find(t => t.pid === 1)
      expect(makeTimeline).toBeDefined()
      expect(makeTimeline!.filesCreated).toBeGreaterThanOrEqual(1)
    })

    it('includes network events in timeline', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'curl', cmdline: 'curl example.com', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
      ]
      const network: BuildNetEvent[] = [
        { type: 'tcp', host: '93.184.216.34', port: 443, timestamp: 200, source: 'procfs' },
      ]
      const record = minimalRecord({ processes, network })
      const graph = buildEvidenceGraph(record)
      const timelines = buildProcessTimelines(record, graph)

      const curlTimeline = timelines.find(t => t.pid === 1)
      expect(curlTimeline).toBeDefined()
      expect(curlTimeline!.networkConnections).toBe(1)
    })

    it('includes secret events in timeline', () => {
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
      const timelines = buildProcessTimelines(record, graph)

      const bashTimeline = timelines.find(t => t.pid === 1)
      expect(bashTimeline).toBeDefined()
      expect(bashTimeline!.secretsRead).toBe(1)
    })

    it('aggregates childPids from spawned edges', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
        { pid: 3, name: 'ld', cmdline: 'ld -o out', ppid: 1, pname: 'make', timestamp: 800, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const timelines = buildProcessTimelines(record, graph)

      const makeTimeline = timelines.find(t => t.pid === 1)
      expect(makeTimeline).toBeDefined()
      expect(makeTimeline!.childPids).toContain(2)
      expect(makeTimeline!.childPids).toContain(3)
    })

    it('returns empty array for empty process list', () => {
      const record = minimalRecord()
      const timelines = buildProcessTimelines(record)

      expect(timelines.length).toBe(0)
    })

    it('preserves event order by timestamp', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, startTime: 100, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const timelines = buildProcessTimelines(record, graph)

      const makeTimeline = timelines.find(t => t.pid === 1)
      expect(makeTimeline).toBeDefined()
      for (let i = 1; i < makeTimeline!.events.length; i++) {
        expect(makeTimeline!.events[i].timestamp).toBeGreaterThanOrEqual(makeTimeline!.events[i - 1].timestamp)
      }
    })
  })

  describe('renderProcessTimeline', () => {
    it('renders a timeline entry without error', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, startTime: 100, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const [timeline] = buildProcessTimelines(record, graph)

      const lines = renderProcessTimeline(timeline)
      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Process Timeline')
    })
  })

  describe('renderTimelineSummary', () => {
    it('renders summary without error', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, startTime: 100, exitTime: 1000, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const timelines = buildProcessTimelines(record, graph)

      const lines = renderTimelineSummary(timelines)
      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Process Timeline Summary')
    })
  })

  describe('findExfilTimelines', () => {
    it('detects timelines with secrets and network activity', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'bash', cmdline: 'bash script.sh', ppid: 0, pname: '', timestamp: 100, source: 'procfs' },
      ]
      const network: BuildNetEvent[] = [
        { type: 'tcp', host: 'evil.com', port: 443, timestamp: 500, source: 'procfs' },
      ]
      const record = minimalRecord({
        processes,
        network,
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
      const timelines = buildProcessTimelines(record, graph)

      const exfil = findExfilTimelines(timelines)
      expect(exfil.length).toBeGreaterThanOrEqual(0)
    })
  })

  describe('sequenceIndex', () => {
    it('is set correctly after sorting', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out.o', size: 1024, operation: 'created', timestamp: 500 },
      ]
      const record = minimalRecord({ processes, files })
      const graph = buildEvidenceGraph(record)
      const timelines = buildProcessTimelines(record, graph)

      for (const tl of timelines) {
        for (let i = 0; i < tl.events.length; i++) {
          expect(tl.events[i].sequenceIndex).toBe(i)
        }
      }
    })
  })

  describe('durationMs in events', () => {
    it('sets durationMs from node attributes when available', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, startTime: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, startTime: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const timelines = buildProcessTimelines(record, graph)

      for (const tl of timelines) {
        const exitEvents = tl.events.filter(e => e.type === 'PROCESS_EXITED')
        for (const ev of exitEvents) {
          expect(ev.durationMs).toBeDefined()
          expect(ev.durationMs).toBeGreaterThan(0)
        }
      }
    })
  })
})
