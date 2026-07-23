import { describe, it, expect } from 'vitest'
import { trackProcessExits, findEphemeralProcesses, renderLifetimeSummary, computeProcessLifetimes } from './process-lifetime'
import { classifyIntent, buildIntentFlow, renderIntentFlow } from './build-intent'
import { updateContract, renderContractViolations } from './build-contract'
import { BuildRecord, BuildContractEntry, BuildIntentFlow } from './build-types'

function makeProc(name: string, pid: number, startTime: number, durationMs: number) {
  return {
    pid, name, cmdline: name, ppid: 0, pname: '',
    timestamp: startTime, startTime, exitTime: startTime + durationMs,
  }
}

describe('Process Lifetime', () => {
  describe('trackProcessExits', () => {
    it('detects exited processes', () => {
      const map = new Map([[1, makeProc('gcc', 1, 100, 50)]])
      const exited = trackProcessExits(new Set(), new Set([1]), map)
      expect(exited.length).toBe(1)
      expect(exited[0].pid).toBe(1)
      expect(exited[0].exitTime).toBeGreaterThan(0)
    })

    it('returns empty when no processes exited', () => {
      const map = new Map([[1, makeProc('gcc', 1, 100, 50)]])
      const exited = trackProcessExits(new Set([1]), new Set([1, 2]), map)
      expect(exited.length).toBe(0)
    })
  })

  describe('findEphemeralProcesses', () => {
    it('finds processes shorter than threshold', () => {
      const procs = [
        makeProc('curl', 1, 100, 50),
        makeProc('gcc', 2, 100, 5000),
      ]
      const ephem = findEphemeralProcesses(procs, 100)
      expect(ephem.length).toBe(1)
      expect(ephem[0].name).toBe('curl')
    })

    it('returns empty when no processes are ephemeral', () => {
      const procs = [makeProc('gcc', 1, 100, 5000)]
      expect(findEphemeralProcesses(procs, 100)).toEqual([])
    })

    it('ignores processes without exitTime', () => {
      const procs = [{ ...makeProc('gcc', 1, 100, 50), exitTime: undefined }]
      expect(findEphemeralProcesses(procs, 100)).toEqual([])
    })
  })

  describe('renderLifetimeSummary', () => {
    it('includes ephemeral processes in output', () => {
      const procs = [makeProc('curl', 1, 100, 30)]
      const out = renderLifetimeSummary(procs)
      expect(out.some(l => l.includes('25ms') || l.includes('50ms') || l.includes('100ms'))).toBe(true)
    })

    it('produces output even without exit times', () => {
      const procs = [{ ...makeProc('gcc', 1, 100, 0), exitTime: undefined }]
      const out = renderLifetimeSummary(procs)
      expect(out.length).toBeGreaterThan(0)
    })
  })
})

describe('Build Intent', () => {
  describe('classifyIntent', () => {
    it('classifies gcc as compile', () => {
      expect(classifyIntent('gcc', 'gcc -c main.c')).toBe('compile')
    })
    it('classifies ld as link', () => {
      expect(classifyIntent('ld', 'ld -o out')).toBe('link')
    })
    it('classifies python as script', () => {
      expect(classifyIntent('python', 'python build.py')).toBe('script')
    })
    it('classifies curl as download', () => {
      expect(classifyIntent('curl', 'curl http://x')).toBe('download')
    })
    it('classifies unknown tools correctly', () => {
      expect(classifyIntent('weird-tool', 'weird-tool')).toBe('unknown')
    })
  })

  describe('buildIntentFlow', () => {
    it('builds flow from process list', () => {
      const record = {
        processes: [
          makeProc('gcc', 1, 100, 500),
          makeProc('ld', 2, 600, 200),
          makeProc('python', 3, 800, 100),
        ],
      } as BuildRecord

      const flow = buildIntentFlow(record)
      expect(flow.observed).toContain('compile')
      expect(flow.observed).toContain('link')
      expect(flow.observed).toContain('script')
    })

    it('returns empty for no processes', () => {
      const record = { processes: [] } as BuildRecord
      const flow = buildIntentFlow(record)
      expect(flow.observed).toEqual([])
    })
  })

  describe('renderIntentFlow', () => {
    it('shows flow and deviations', () => {
      const flow: BuildIntentFlow = {
        expected: ['configure', 'compile', 'link'],
        observed: ['compile', 'download', 'link'],
        deviations: ['Unexpected order'],
      }
      const out = renderIntentFlow(flow)
      expect(out.some(l => l.includes('Expected'))).toBe(true)
      expect(out.some(l => l.includes('Observed'))).toBe(true)
      expect(out.some(l => l.includes('Deviations'))).toBe(true)
    })

    it('shows success when no deviations', () => {
      const flow: BuildIntentFlow = {
        expected: ['compile', 'link'],
        observed: ['compile', 'link'],
        deviations: [],
      }
      const out = renderIntentFlow(flow)
      expect(out.some(l => l.includes('matches'))).toBe(true)
    })
  })
})

describe('Build Contract', () => {
  describe('updateContract', () => {
    it('creates entries for new tools', () => {
      const record = {
        processes: [makeProc('gcc', 1, 100, 500), makeProc('ld', 2, 600, 200)],
      } as BuildRecord

      const { contract, violations } = updateContract(record, [], 2)
      expect(contract.length).toBe(2)
      expect(violations.length).toBe(0)
    })

    it('detects violation when new tool appears after threshold', () => {
      const existing: BuildContractEntry[] = [
        { tool: 'gcc', firstSeen: 1, lastSeen: 1, count: 5, intent: 'compile' },
        { tool: 'ld', firstSeen: 1, lastSeen: 1, count: 5, intent: 'link' },
        { tool: 'make', firstSeen: 1, lastSeen: 1, count: 5, intent: 'package' },
      ]

      const record = {
        processes: [
          makeProc('gcc', 1, 100, 500),
          makeProc('ld', 2, 600, 200),
          makeProc('make', 3, 800, 300),
          makeProc('curl', 4, 900, 50),
        ],
      } as BuildRecord

      const { contract, violations } = updateContract(record, existing, 2)
      expect(violations.some(v => v.tool === 'curl')).toBe(true)
    })

    it('updates count for existing tools', () => {
      const existing: BuildContractEntry[] = [
        { tool: 'gcc', firstSeen: 1, lastSeen: 1, count: 3, intent: 'compile' },
      ]
      const record = {
        processes: [makeProc('gcc', 1, 100, 500)],
      } as BuildRecord

      const { contract } = updateContract(record, existing, 2)
      const gccEntry = contract.find(e => e.tool === 'gcc')
      expect(gccEntry?.count).toBe(4)
    })
  })

  describe('renderContractViolations', () => {
    it('shows no violations message', () => {
      const lines = renderContractViolations([])
      expect(lines.some(l => l.includes('No contract violations'))).toBe(true)
    })

    it('renders violation details', () => {
      const v = renderContractViolations([
        { tool: 'curl', intent: 'download', reason: 'curl was unexpected', severity: 'critical' },
      ])
      expect(v.some(l => l.includes('CRITICAL'))).toBe(true)
      expect(v.some(l => l.includes('curl'))).toBe(true)
    })
  })
})
