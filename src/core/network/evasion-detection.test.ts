import { describe, it, expect } from 'vitest'
import {
  detectOrphanProcesses,
  detectDnsOverHttps,
  detectFilelessExecution,
  inferEvidenceSource,
} from './evasion-detection'
import { BuildProcessEvent, BuildNetEvent } from './build-types'

describe('evasion-detection', () => {
  describe('detectOrphanProcesses', () => {
    it('detects process with ppid not in process set', () => {
      const procs: BuildProcessEvent[] = [
        { pid: 1, name: 'gcc', cmdline: 'gcc -c', ppid: 0, pname: '', timestamp: 100 },
        { pid: 500, name: 'injected', cmdline: './evil', ppid: 999, pname: '', timestamp: 100 },
      ]
      const orphans = detectOrphanProcesses(procs)
      expect(orphans.length).toBe(1)
      expect(orphans[0].name).toBe('injected')
      expect(orphans[0].reason).toContain('ptrace')
    })

    it('does not flag valid parent-child relationships', () => {
      const procs: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100 },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 100 },
      ]
      expect(detectOrphanProcesses(procs)).toEqual([])
    })

    it('handles self-referencing pid gracefully', () => {
      const procs: BuildProcessEvent[] = [
        { pid: 1, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: '', timestamp: 100 },
      ]
      expect(detectOrphanProcesses(procs)).toEqual([])
    })
  })

  describe('detectDnsOverHttps', () => {
    it('detects known DoH providers', () => {
      const nets: BuildNetEvent[] = [
        { type: 'tcp', host: 'dns.cloudflare.com', port: 443, timestamp: 100 },
        { type: 'tcp', host: 'dns.google', port: 443, timestamp: 100 },
        { type: 'tcp', host: 'example.com', port: 443, timestamp: 100 },
      ]
      const doh = detectDnsOverHttps(nets)
      expect(doh.length).toBe(2)
      expect(doh[0].host).toContain('cloudflare')
      expect(doh[1].host).toContain('google')
    })

    it('returns empty for non-DoH traffic', () => {
      const nets: BuildNetEvent[] = [
        { type: 'tcp', host: 'example.com', port: 443, timestamp: 100 },
      ]
      expect(detectDnsOverHttps(nets)).toEqual([])
    })
  })

  describe('detectFilelessExecution', () => {
    it('detects /dev/fd execution', () => {
      const procs: BuildProcessEvent[] = [
        { pid: 1, name: 'sh', cmdline: 'sh /dev/fd/9', ppid: 0, pname: '', timestamp: 100 },
      ]
      const fileless = detectFilelessExecution(procs)
      expect(fileless.length).toBe(1)
    })

    it('detects pipe execution', () => {
      const procs: BuildProcessEvent[] = [
        { pid: 1, name: 'cat', cmdline: 'cat pipe:[12345]', ppid: 0, pname: '', timestamp: 100 },
      ]
      const fileless = detectFilelessExecution(procs)
      expect(fileless.length).toBe(1)
    })

    it('does not flag normal execution', () => {
      const procs: BuildProcessEvent[] = [
        { pid: 1, name: 'gcc', cmdline: 'gcc -c main.c', ppid: 0, pname: '', timestamp: 100 },
      ]
      expect(detectFilelessExecution(procs)).toEqual([])
    })
  })

  describe('inferEvidenceSource', () => {
    it('returns procfs for observe-only mode', () => {
      const source = inferEvidenceSource('linux', { observeOnly: true })
      expect(source).toBe('procfs')
    })

    it('returns polling for unknown platform', () => {
      const source = inferEvidenceSource('darwin')
      expect(source).toBe('polling')
    })
  })
})
