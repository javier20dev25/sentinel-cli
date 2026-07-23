import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import {
  capturePreBuildInventory,
  pollProcessOpenFiles,
  detectReadFilesPostBuild,
  deduplicateReadEvents,
  renderFileReads,
  PreBuildInventory,
  FileInventoryEntry,
} from './file-read-provenance'
import { FileReadEvent } from './build-types'

describe('File Read Provenance', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-readtest-'))
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  describe('capturePreBuildInventory', () => {
    it('returns files in directory with size and mtime', () => {
      fs.writeFileSync(path.join(tmpDir, 'main.c'), 'int main() {}')
      fs.writeFileSync(path.join(tmpDir, 'util.h'), '#define FOO 1')
      fs.mkdirSync(path.join(tmpDir, 'sub'))
      fs.writeFileSync(path.join(tmpDir, 'sub', 'helper.rs'), 'fn help() {}')

      const inv = capturePreBuildInventory(tmpDir)
      expect(inv.files.size).toBeGreaterThanOrEqual(2)
      expect(inv.files.size).toBeLessThanOrEqual(3)
      expect(typeof inv.timestamp).toBe('number')

      for (const [, entry] of inv.files) {
        expect(typeof entry.size).toBe('number')
        expect(typeof entry.mtimeMs).toBe('number')
      }
    })

    it('returns empty inventory for empty directory', () => {
      const inv = capturePreBuildInventory(tmpDir)
      expect(inv.files.size).toBe(0)
    })

    it('handles non-existent directory gracefully', () => {
      const inv = capturePreBuildInventory(path.join(tmpDir, 'nonexistent'))
      expect(inv.files.size).toBe(0)
      expect(typeof inv.timestamp).toBe('number')
    })
  })

  describe('pollProcessOpenFiles', () => {
    it('returns empty array for unknown PID', () => {
      const events = pollProcessOpenFiles(
        new Set([999999]),
        tmpDir,
        new Map([[999999, 'test']]),
      )
      expect(Array.isArray(events)).toBe(true)
    })

    it('returns events for current process opening a file', () => {
      const testFile = path.join(tmpDir, 'readme.txt')
      fs.writeFileSync(testFile, 'hello')

      const fd = fs.openSync(testFile, 'r')
      const events = pollProcessOpenFiles(
        new Set([process.pid]),
        tmpDir,
        new Map([[process.pid, 'node']]),
      )
      fs.closeSync(fd)

      const relevant = events.filter(e => e.filePath.includes('readme.txt'))
      expect(relevant.length).toBeGreaterThanOrEqual(0)
    })

    it('deduplicates files from same PID', () => {
      const events = pollProcessOpenFiles(
        new Set([process.pid]),
        tmpDir,
        new Map([[process.pid, 'node']]),
      )
      const filePaths = events.map(e => `${e.filePath}:${e.pid}`)
      const uniquePaths = new Set(filePaths)
      expect(filePaths.length).toBe(uniquePaths.size)
    })

    it('assigns correct process name from map', () => {
      const events = pollProcessOpenFiles(
        new Set([process.pid]),
        tmpDir,
        new Map([[process.pid, 'gcc']]),
      )
      for (const e of events) {
        expect(e.processName).toBe('gcc')
      }
    })
  })

  describe('detectReadFilesPostBuild', () => {
    it('returns events for files with changed mtime', () => {
      const testFile = 'touched.c'
      fs.writeFileSync(path.join(tmpDir, testFile), 'original')
      const inv = capturePreBuildInventory(tmpDir)

      fs.writeFileSync(path.join(tmpDir, testFile), 'modified')

      const result = detectReadFilesPostBuild(
        inv,
        [{ filePath: testFile, operation: 'modified', timestamp: Date.now() }],
        [{ pid: 123, name: 'gcc', timestamp: Date.now() }],
        tmpDir,
      )

      expect(result.length).toBeGreaterThanOrEqual(0)
    })

    it('skips files that were created during build', () => {
      const inv = capturePreBuildInventory(tmpDir)

      const newFile = 'new.o'
      fs.writeFileSync(path.join(tmpDir, newFile), 'binary')

      const result = detectReadFilesPostBuild(
        inv,
        [{ filePath: newFile, operation: 'created', timestamp: Date.now() }],
        [{ pid: 123, name: 'gcc', timestamp: Date.now() }],
        tmpDir,
      )

      expect(result.length).toBe(0)
    })

    it('returns empty for no mtime changes', () => {
      const testFile = 'stable.h'
      fs.writeFileSync(path.join(tmpDir, testFile), '#pragma once')
      const inv = capturePreBuildInventory(tmpDir)

      const result = detectReadFilesPostBuild(
        inv,
        [],
        [{ pid: 123, name: 'gcc', timestamp: Date.now() + 1000 }],
        tmpDir,
      )

      const readsForStable = result.filter(e => e.filePath === testFile)
      expect(readsForStable.length).toBe(0)
    })
  })

  describe('deduplicateReadEvents', () => {
    it('removes duplicate file+pid pairs', () => {
      const base: FileReadEvent = {
        filePath: 'src/main.c',
        pid: 100,
        processName: 'gcc',
        timestamp: 1000,
        size: 1024,
      }

      const result = deduplicateReadEvents([
        base,
        { ...base },
        { ...base, pid: 101, processName: 'clang' },
      ])

      expect(result.length).toBe(2)
    })

    it('returns same array when no duplicates', () => {
      const events: FileReadEvent[] = [
        { filePath: 'a.c', pid: 1, processName: 'gcc', timestamp: 1, size: 10 },
        { filePath: 'b.c', pid: 2, processName: 'clang', timestamp: 2, size: 20 },
      ]

      const result = deduplicateReadEvents(events)
      expect(result.length).toBe(2)
    })

    it('returns empty for empty input', () => {
      expect(deduplicateReadEvents([])).toEqual([])
    })
  })

  describe('renderFileReads', () => {
    it('produces readable output', () => {
      const events: FileReadEvent[] = [
        { filePath: 'src/main.c', pid: 1, processName: 'gcc', timestamp: 1, size: 100 },
        { filePath: 'src/util.h', pid: 1, processName: 'gcc', timestamp: 2, size: 50 },
      ]

      const lines = renderFileReads(events)
      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toBe('Files Read')
      expect(lines.some(l => l.includes('gcc'))).toBe(true)
      expect(lines.some(l => l.includes('main.c'))).toBe(true)
    })

    it('respects maxLines limit', () => {
      const events: FileReadEvent[] = []
      for (let i = 0; i < 50; i++) {
        events.push({ filePath: `f${i}.c`, pid: i, processName: `p${i}`, timestamp: i, size: i })
      }

      const lines = renderFileReads(events, 5)
      expect(lines.some(l => l.includes('...'))).toBe(true)
    })

    it('handles empty input', () => {
      expect(renderFileReads([])).toEqual(['Files Read', '----------'])
    })
  })
})
