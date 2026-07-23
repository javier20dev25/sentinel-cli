import { describe, it, expect } from 'vitest'
import {
  evidenceConfidence,
  processConfidence,
  fileReadConfidence,
  netEventConfidence,
  fileEventConfidence,
  computeObservationConfidence,
  renderObservationConfidence,
} from './evidence-reliability'
import { BuildProcessEvent, BuildFileEvent, BuildNetEvent, FileReadEvent } from './build-types'

describe('evidence-reliability', () => {
  describe('evidenceConfidence', () => {
    it('returns 98 for ETW', () => {
      expect(evidenceConfidence('etw')).toBe(98)
    })
    it('returns 97 for eBPF', () => {
      expect(evidenceConfidence('ebpf')).toBe(97)
    })
    it('returns 42 for mtime heuristic', () => {
      expect(evidenceConfidence('mtime_heuristic')).toBe(42)
    })
    it('returns 50 for unknown source', () => {
      expect(evidenceConfidence('unknown' as any)).toBe(50)
    })
  })

  describe('processConfidence', () => {
    it('uses source base when available', () => {
      const proc: BuildProcessEvent = {
        pid: 1, name: 'gcc', cmdline: 'gcc -c', ppid: 0, pname: '',
        timestamp: 100, startTime: 50, exitTime: 200,
        source: 'etw',
      }
      expect(processConfidence(proc)).toBe(100)
    })
    it('returns lower for polling without exit time', () => {
      const proc: BuildProcessEvent = {
        pid: 1, name: 'gcc', cmdline: 'gcc -c', ppid: 0, pname: '',
        timestamp: 100,
        source: 'polling',
      }
      expect(processConfidence(proc)).toBe(65)
    })
    it('handles no source with default 65', () => {
      const proc: BuildProcessEvent = {
        pid: 1, name: 'gcc', cmdline: 'gcc -c', ppid: 0, pname: '',
        timestamp: 100, startTime: 50,
      }
      const c = processConfidence(proc)
      expect(c).toBeGreaterThanOrEqual(65)
      expect(c).toBeLessThanOrEqual(80)
    })
  })

  describe('fileReadConfidence', () => {
    it('returns higher with source and size', () => {
      const event: FileReadEvent = {
        filePath: '/tmp/secret.env', pid: 1, processName: 'bash',
        timestamp: 100, size: 1024, source: 'ebpf',
      }
      expect(fileReadConfidence(event)).toBe(100)
    })
    it('returns lower without source or size', () => {
      const event: FileReadEvent = {
        filePath: '/tmp/x', pid: 1, processName: 'cat',
        timestamp: 100, size: 0,
      }
      expect(fileReadConfidence(event)).toBe(50)
    })
  })

  describe('netEventConfidence', () => {
    it('returns higher with source and port', () => {
      const event: BuildNetEvent = {
        type: 'tcp', host: 'example.com', port: 443,
        timestamp: 100, source: 'etw',
      }
      expect(netEventConfidence(event)).toBe(100)
    })
    it('returns lower without port', () => {
      const event: BuildNetEvent = {
        type: 'dns', host: 'example.com',
        timestamp: 100,
      }
      expect(netEventConfidence(event)).toBe(60)
    })
  })

  describe('fileEventConfidence', () => {
    it('returns higher with sha256', () => {
      const event: BuildFileEvent = {
        filePath: '/tmp/a.o', size: 1024, operation: 'created',
        timestamp: 100, sha256: 'abc', source: 'procfs',
      }
      expect(fileEventConfidence(event)).toBe(95)
    })
    it('returns lower without sha256', () => {
      const event: BuildFileEvent = {
        filePath: '/tmp/a.o', size: 1024, operation: 'created',
        timestamp: 100,
      }
      expect(fileEventConfidence(event)).toBe(50)
    })
  })

  describe('computeObservationConfidence', () => {
    it('returns 0 for empty inputs', () => {
      const oc = computeObservationConfidence([], [], [], [])
      expect(oc.overall).toBe(0)
      expect(oc.coverage).toBe(0)
      expect(oc.sources).toEqual([])
    })

    it('computes high confidence for ETW-sourced events', () => {
      const procs: BuildProcessEvent[] = [{
        pid: 1, name: 'gcc', cmdline: 'gcc -c', ppid: 0, pname: '',
        timestamp: 100, startTime: 50, exitTime: 200,
        source: 'etw',
      }]
      const files: BuildFileEvent[] = [{
        filePath: '/tmp/a.o', size: 1024, operation: 'created',
        timestamp: 100, sha256: 'abc', source: 'ebpf',
      }]
      const nets: BuildNetEvent[] = [{
        type: 'tcp', host: 'x.com', port: 443,
        timestamp: 100, source: 'etw',
      }]
      const reads: FileReadEvent[] = [{
        filePath: '/tmp/secret', pid: 1, processName: 'bash',
        timestamp: 100, size: 512, source: 'ebpf',
      }]
      const oc = computeObservationConfidence(procs, files, nets, reads)
      expect(oc.overall).toBeGreaterThan(80)
      expect(oc.coverage).toBe(100)
      expect(oc.sources).toContain('etw')
      expect(oc.sources).toContain('ebpf')
    })

    it('computes lower confidence for polling-sourced events', () => {
      const procs: BuildProcessEvent[] = [{
        pid: 1, name: 'gcc', cmdline: 'gcc -c', ppid: 0, pname: '',
        timestamp: 100, source: 'polling',
      }]
      const oc = computeObservationConfidence(procs, [], [], [])
      expect(oc.overall).toBeLessThan(70)
    })
  })

  describe('renderObservationConfidence', () => {
    it('renders output lines', () => {
      const oc = computeObservationConfidence([{
        pid: 1, name: 'gcc', cmdline: 'gcc -c', ppid: 0, pname: '',
        timestamp: 100, source: 'etw',
      }], [], [], [])
      const lines = renderObservationConfidence(oc)
      expect(lines.length).toBeGreaterThan(5)
      expect(lines.some(l => l.includes('Overall'))).toBe(true)
      expect(lines.some(l => l.includes('Sources'))).toBe(true)
    })
  })
})
