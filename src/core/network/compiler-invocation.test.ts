import { describe, it, expect } from 'vitest'
import {
  isCompilerOrLinker,
  extractCompilerInvocation,
  analyzeCompilerInvocations,
  renderCompilerInvocations,
} from './compiler-invocation'
import { BuildProcessEvent } from './build-types'

describe('compiler-invocation', () => {
  describe('isCompilerOrLinker', () => {
    it('identifies compilers', () => {
      expect(isCompilerOrLinker('gcc')).toBe(true)
      expect(isCompilerOrLinker('clang++')).toBe(true)
      expect(isCompilerOrLinker('rustc')).toBe(true)
    })

    it('identifies linkers', () => {
      expect(isCompilerOrLinker('ld')).toBe(true)
      expect(isCompilerOrLinker('ld.lld')).toBe(true)
    })

    it('rejects non-compilers', () => {
      expect(isCompilerOrLinker('python')).toBe(false)
      expect(isCompilerOrLinker('make')).toBe(false)
    })
  })

  describe('extractCompilerInvocation', () => {
    it('extracts basic gcc invocation', () => {
      const proc: BuildProcessEvent = {
        pid: 100, name: 'gcc', cmdline: 'gcc -O2 -c main.c -o main.o',
        ppid: 1, pname: 'make', timestamp: 1000,
      }
      const inv = extractCompilerInvocation(proc, '/build')
      expect(inv).not.toBeNull()
      expect(inv!.tool).toBe('gcc')
      expect(inv!.inputFiles).toContain('main.c')
      expect(inv!.outputFiles).toContain('main.o')
      expect(inv!.flags).toContain('-O2')
      expect(inv!.hasResponseFile).toBe(false)
    })

    it('extracts response file usage', () => {
      const proc: BuildProcessEvent = {
        pid: 101, name: 'gcc', cmdline: 'gcc @response.txt main.c -o out',
        ppid: 1, pname: 'make', timestamp: 1000,
      }
      const inv = extractCompilerInvocation(proc, '/build')
      expect(inv).not.toBeNull()
      expect(inv!.hasResponseFile).toBe(true)
      expect(inv!.responseFiles).toContain('response.txt')
    })

    it('extracts defines', () => {
      const proc: BuildProcessEvent = {
        pid: 102, name: 'gcc', cmdline: 'gcc -DDEBUG=1 -DVERSION=\\"2.0\\" main.c',
        ppid: 1, pname: 'make', timestamp: 1000,
      }
      const inv = extractCompilerInvocation(proc, '/build')
      expect(inv).not.toBeNull()
      expect(inv!.defines.length).toBeGreaterThanOrEqual(1)
    })

    it('returns null for non-compiler', () => {
      const proc: BuildProcessEvent = {
        pid: 200, name: 'python', cmdline: 'python build.py',
        ppid: 1, pname: 'bash', timestamp: 1000,
      }
      expect(extractCompilerInvocation(proc, '/build')).toBeNull()
    })

    it('detects suspicious flags', () => {
      const proc: BuildProcessEvent = {
        pid: 103, name: 'gcc', cmdline: 'gcc -fno-stack-protector -z execstack main.c',
        ppid: 1, pname: 'make', timestamp: 1000,
      }
      const identity = analyzeCompilerInvocations([proc], '/build')
      expect(identity.suspiciousInvocations.length).toBeGreaterThan(0)
    })
  })

  describe('analyzeCompilerInvocations', () => {
    it('aggregates multiple invocations', () => {
      const procs: BuildProcessEvent[] = [
        { pid: 1, name: 'gcc', cmdline: 'gcc -O2 -c a.c', ppid: 1, pname: 'make', timestamp: 1000 },
        { pid: 2, name: 'gcc', cmdline: 'gcc -O2 -c b.c', ppid: 1, pname: 'make', timestamp: 2000 },
        { pid: 3, name: 'ld', cmdline: 'ld a.o b.o -o out', ppid: 1, pname: 'make', timestamp: 3000 },
      ]
      const identity = analyzeCompilerInvocations(procs, '/build')
      expect(identity.totalInvocations).toBe(3)
      expect(identity.uniqueFlags).toContain('-O2')
    })
  })

  describe('renderCompilerInvocations', () => {
    it('renders empty state', () => {
      const result = renderCompilerInvocations({ invocations: [], totalInvocations: 0, uniqueFlags: [], suspiciousInvocations: [] })
      expect(result[0]).toBe('No compiler invocations detected')
    })
  })
})
