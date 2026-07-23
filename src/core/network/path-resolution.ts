import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import { execFileSync } from 'child_process'
import { ToolResolution, PathState } from './build-types'

export interface PathDiff {
  type: 'reordered' | 'prepended' | 'appended' | 'removed' | 'shadowed'
  detail: string
  severity: 'info' | 'warning' | 'critical'
}

export function capturePathState(cwd: string): PathState {
  const pathValue = process.env.PATH || ''
  const entries = pathValue.split(path.delimiter).filter(Boolean)
  const resolutions: ToolResolution[] = []

  const toolsToResolve = [
    'gcc', 'g++', 'clang', 'clang++', 'cc', 'c++',
    'ld', 'ld.lld', 'ar', 'ranlib', 'strip', 'objcopy', 'nm', 'readelf',
    'make', 'cmake', 'ninja', 'meson',
    'python', 'python3', 'node', 'rustc', 'cargo', 'go',
    'javac', 'java',
    'curl', 'wget', 'git',
  ]

  const seen = new Set<string>()

  for (const tool of toolsToResolve) {
    if (seen.has(tool)) continue
    seen.add(tool)

    let entry: string | null = null
    let resolved: string | null = null
    for (let i = 0; i < entries.length; i++) {
      const fullPath = path.join(entries[i], tool)
      try {
        if (fs.existsSync(fullPath) || fs.existsSync(fullPath + '.exe')) {
          entry = entries[i]
          resolved = fullPath
          if (fs.existsSync(fullPath + '.exe')) resolved = fullPath + '.exe'
          break
        }
      } catch {}
    }

    if (!resolved) continue

    try {
      const whichPath = execFileSync('where', [tool], { stdio: 'pipe', timeout: 2000, encoding: 'utf8' })
        .split('\n')[0].trim()
      if (whichPath) resolved = whichPath
    } catch {
      try {
        const whichPath2 = execFileSync('whereis', [tool], { stdio: 'pipe', timeout: 2000, encoding: 'utf8' })
          .split(/\s+/)[1]
        if (whichPath2) resolved = whichPath2
      } catch {}
    }

    if (!resolved) continue

    try {
      const realPath = fs.realpathSync(resolved)
      const content = fs.readFileSync(resolved)
      const sha256 = crypto.createHash('sha256').update(content).digest('hex')
      let version = ''
      try {
        const verOut = execFileSync(resolved, ['--version'], { stdio: 'pipe', timeout: 2000, encoding: 'utf8' })
        version = verOut.split('\n')[0].trim().substring(0, 120)
      } catch {}

      resolutions.push({
        toolName: tool,
        resolvedPath: resolved,
        realPath,
        sha256,
        version,
        fromPathEntry: entry || '',
        pathIndex: entry ? entries.indexOf(entry) : -1,
      })
    } catch {}
  }

  return {
    pathValue,
    entries,
    resolutions,
    timestamp: Date.now(),
  }
}

export function diffPathStates(prev: PathState, curr: PathState): PathDiff[] {
  const diffs: PathDiff[] = []

  const prevStr = prev.entries.join(path.delimiter)
  const currStr = curr.entries.join(path.delimiter)

  if (prevStr === currStr) return diffs

  if (prev.entries.length < curr.entries.length) {
    for (let i = 0; i < curr.entries.length; i++) {
      if (i >= prev.entries.length || prev.entries[i] !== curr.entries[i]) {
        if (!prev.entries.includes(curr.entries[i])) {
          diffs.push({
            type: 'prepended',
            detail: `PATH entry "${curr.entries[i]}" added at position ${i}`,
            severity: 'critical',
          })
        }
        break
      }
    }

    for (let i = 0; i < curr.entries.length; i++) {
      if (!prev.entries.includes(curr.entries[i])) {
        const isAlreadyReported = diffs.some(d => d.detail.includes(curr.entries[i]))
        if (!isAlreadyReported) {
          const existing = diffs.find(d => d.type === 'prepended')
          if (!existing) {
            diffs.push({
              type: 'appended',
              detail: `PATH entry "${curr.entries[i]}" added`,
              severity: 'warning',
            })
          }
        }
      }
    }
  }

  for (const prevEntry of prev.entries) {
    if (!curr.entries.includes(prevEntry)) {
      diffs.push({
        type: 'removed',
        detail: `PATH entry "${prevEntry}" removed`,
        severity: 'warning',
      })
    }
  }

  if (prev.entries.length === curr.entries.length) {
    for (let i = 0; i < prev.entries.length; i++) {
      if (prev.entries[i] !== curr.entries[i]) {
        diffs.push({
          type: 'reordered',
          detail: `PATH[${i}] changed from "${prev.entries[i]}" to "${curr.entries[i]}"`,
          severity: 'warning',
        })
      }
    }
  }

  const prevResolvedMap = new Map(prev.resolutions.map(r => [r.toolName, r]))
  for (const currRes of curr.resolutions) {
    const prevRes = prevResolvedMap.get(currRes.toolName)
    if (prevRes && prevRes.realPath !== currRes.realPath) {
      diffs.push({
        type: 'shadowed',
        detail: `${currRes.toolName} resolved to "${currRes.realPath}" (was "${prevRes.realPath}")`,
        severity: 'critical',
      })
    }
  }

  return diffs
}

export function renderPathDiff(diffs: PathDiff[]): string[] {
  if (diffs.length === 0) return ['PATH unchanged']

  const lines: string[] = ['PATH Changes']
  for (const d of diffs) {
    const icon = d.severity === 'critical' ? '!' : d.severity === 'warning' ? '~' : '·'
    lines.push(`  ${icon} [${d.severity.toUpperCase()}] ${d.detail}`)
  }
  return lines
}

export function renderPathState(state: PathState): string[] {
  const lines: string[] = [
    'PATH State',
    '----------',
    `PATH: ${state.pathValue.substring(0, 200)}${state.pathValue.length > 200 ? '...' : ''}`,
    `Entries: ${state.entries.length}`,
    '',
    'Tool Resolutions:',
  ]

  for (const r of state.resolutions) {
    const shortSha = r.sha256.substring(0, 12)
    lines.push(`  ${r.toolName}: ${r.realPath} (SHA256 ${shortSha})`)
    if (r.version) lines.push(`    version: ${r.version}`)
  }

  return lines
}
