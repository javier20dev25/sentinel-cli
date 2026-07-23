import * as fs from 'fs'
import * as path from 'path'
import { execFileSync } from 'child_process'
import { FileReadEvent } from './build-types'

export interface FileInventoryEntry {
  size: number
  mtimeMs: number
}

export interface PreBuildInventory {
  files: Map<string, FileInventoryEntry>
  timestamp: number
}

export function capturePreBuildInventory(cwd: string): PreBuildInventory {
  const files = new Map<string, FileInventoryEntry>()
  const timestamp = Date.now()

  try {
    walkDirectory(cwd, files, cwd)
  } catch {}

  return { files, timestamp }
}

function walkDirectory(dir: string, result: Map<string, FileInventoryEntry>, root: string): void {
  let entries: string[] = []
  try {
    entries = fs.readdirSync(dir)
  } catch { return }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry)
    try {
      const stat = fs.statSync(fullPath)
      if (stat.isDirectory()) {
        if (!entry.startsWith('.') && !entry.includes('node_modules') && !entry.includes('.git')) {
          walkDirectory(fullPath, result, root)
        }
      } else if (stat.isFile()) {
        const relPath = path.relative(root, fullPath)
        result.set(relPath, { size: stat.size, mtimeMs: stat.mtimeMs })
      }
    } catch {}
  }
}

export function pollProcessOpenFiles(
  pids: Set<number>,
  cwd: string,
  processNames: Map<number, string>,
): FileReadEvent[] {
  const events: FileReadEvent[] = []
  const now = Date.now()

  for (const pid of pids) {
    try {
      const files = getOpenFilesForPid(pid, cwd)
      for (const f of files) {
        events.push({
          filePath: f,
          pid,
          processName: processNames.get(pid) || 'unknown',
          timestamp: now,
          size: getFileSize(f),
        })
      }
    } catch {}
  }

  return events
}

function getOpenFilesForPid(pid: number, cwd: string): string[] {
  const result: string[] = []

  if (process.platform === 'linux') {
    try {
      const fdDir = `/proc/${pid}/fd`
      const fds = fs.readdirSync(fdDir)
      for (const fd of fds) {
        try {
          const linkPath = fs.readlinkSync(path.join(fdDir, fd))
          if (linkPath.startsWith('/') && linkPath.startsWith(cwd, 0)) {
            const relPath = path.relative(cwd, linkPath)
            if (!result.includes(relPath)) result.push(relPath)
          }
        } catch {}
      }
    } catch {}
  } else if (process.platform === 'win32') {
    try {
      const out = execFileSync('powershell', [
        '-NoProfile', '-Command',
        `Get-Process -Id ${pid} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Modules | Select-Object -ExpandProperty FileName`,
      ], { stdio: 'pipe', timeout: 3000, encoding: 'utf8' })

      for (const line of out.split('\n')) {
        const trimmed = line.trim()
        if (trimmed && trimmed.startsWith(cwd, 0)) {
          const relPath = path.relative(cwd, trimmed)
          if (!result.includes(relPath)) result.push(relPath)
        }
      }
    } catch {}

    try {
      const out2 = execFileSync('powershell', [
        '-NoProfile', '-Command',
        `Get-Process -Id ${pid} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Handle`,
      ], { stdio: 'pipe', timeout: 3000, encoding: 'utf8' })

      for (const line of out2.split('\n')) {
        const trimmed = line.trim()
        if (trimmed && trimmed.startsWith(cwd, 0)) {
          const relPath = path.relative(cwd, trimmed)
          if (!result.includes(relPath)) result.push(relPath)
        }
      }
    } catch {}
  }

  return [...new Set(result)]
}

function getFileSize(filePath: string): number {
  try {
    const fullPath = path.resolve(filePath)
    return fs.statSync(fullPath).size
  } catch { return 0 }
}

export function detectReadFilesPostBuild(
  preInventory: PreBuildInventory,
  buildFiles: { filePath: string; operation: string; timestamp: number }[],
  buildProcesses: { pid: number; name: string; timestamp: number }[],
  cwd: string,
): FileReadEvent[] {
  const events: FileReadEvent[] = []
  const now = Date.now()
  const createdPaths = new Set(buildFiles.filter(f => f.operation === 'created').map(f => f.filePath))

  for (const [relPath, entry] of preInventory.files) {
    const fullPath = path.join(cwd, relPath)
    try {
      const stat = fs.statSync(fullPath)
      if (createdPaths.has(relPath)) continue

      const mtimeDelta = Math.abs(stat.mtimeMs - entry.mtimeMs)
      if (mtimeDelta > 1) {
        const nearest = buildProcesses
          .filter(p => Math.abs(p.timestamp - now) < 30000)
          .sort((a, b) => Math.abs(a.timestamp - now) - Math.abs(b.timestamp - now))
        const nearestProc = nearest[0]
        if (nearestProc) {
          events.push({
            filePath: relPath,
            pid: nearestProc.pid,
            processName: nearestProc.name,
            timestamp: now,
            size: stat.size,
          })
        }
      }
    } catch {}
  }

  return events
}

export function deduplicateReadEvents(events: FileReadEvent[]): FileReadEvent[] {
  const seen = new Set<string>()
  return events.filter(e => {
    const key = `${e.filePath}:${e.pid}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

export function renderFileReads(events: FileReadEvent[], maxLines = 20): string[] {
  const lines: string[] = ['Files Read', '----------']
  const grouped = new Map<string, { processName: string; files: string[] }>()

  for (const e of events) {
    const key = e.processName
    if (!grouped.has(key)) grouped.set(key, { processName: key, files: [] })
    grouped.get(key)!.files.push(e.filePath)
  }

  let count = 0
  for (const [name, info] of grouped) {
    if (count >= maxLines) {
      lines.push(`  ... and ${events.length - count} more`)
      break
    }
    for (const f of info.files.slice(0, 5)) {
      lines.push(`  ${name} → ${f}`)
      count++
    }
    if (info.files.length > 5) {
      lines.push(`  ${name} → ... (${info.files.length - 5} more)`)
      count++
    }
  }

  return lines
}
