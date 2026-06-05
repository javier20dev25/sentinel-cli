import * as fs from 'fs'

export interface LockfileEntry {
  name: string
  version: string
  resolved: string
  integrity: string
  dependencies: string[]
}

export interface LockfileResult {
  entries: LockfileEntry[]
  format: 'npm-v6' | 'npm-v7' | 'yarn' | 'unknown'
}

export class LockfileParser {
  detectFormat(content: string): string {
    const trimmed = content.trim()
    if (!trimmed) return 'unknown'

    const firstLine = trimmed.split('\n')[0].trim()

    if (firstLine.startsWith('#')) {
      return 'yarn'
    }

    if (trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed)
        if (parsed.packages) return 'npm-v7'
        if (parsed.dependencies) return 'npm-v6'
      } catch {
        return 'unknown'
      }
    }

    if (/^[a-zA-Z@]/.test(firstLine) && firstLine.includes('@') && firstLine.endsWith(':')) {
      return 'yarn'
    }

    return 'unknown'
  }

  parsePackageLock(content: string): LockfileResult {
    let parsed: any
    try {
      parsed = JSON.parse(content)
    } catch {
      return { entries: [], format: 'unknown' }
    }

    if (parsed.packages && typeof parsed.packages === 'object') {
      return this.parseNpmV7(parsed)
    }

    if (parsed.dependencies && typeof parsed.dependencies === 'object') {
      return this.parseNpmV6(parsed)
    }

    return { entries: [], format: 'unknown' }
  }

  private parseNpmV7(parsed: any): LockfileResult {
    const entries: LockfileEntry[] = []

    for (const [key, val] of Object.entries(parsed.packages)) {
      if (key === '') continue
      const info = val as any
      if (!info.version) continue

      const name = key.replace(/^node_modules\//, '')
      const deps = info.dependencies ? Object.keys(info.dependencies) : []

      entries.push({
        name,
        version: info.version,
        resolved: info.resolved || '',
        integrity: info.integrity || '',
        dependencies: deps,
      })
    }

    return { entries, format: 'npm-v7' }
  }

  private parseNpmV6(parsed: any): LockfileResult {
    const entries: LockfileEntry[] = []

    for (const [name, val] of Object.entries(parsed.dependencies)) {
      const info = val as any
      if (!info.version) continue

      const deps = info.dependencies ? Object.keys(info.dependencies) : []

      entries.push({
        name,
        version: info.version,
        resolved: info.resolved || '',
        integrity: info.integrity || '',
        dependencies: deps,
      })
    }

    return { entries, format: 'npm-v6' }
  }

  parseYarnLock(content: string): LockfileResult {
    const entries: LockfileEntry[] = []
    const lines = content.split(/\r?\n/)

    let currentName = ''
    let currentVersion = ''
    let currentResolved = ''
    let currentIntegrity = ''
    let currentDeps: string[] = []
    let inBlock = false
    let inDeps = false

    for (const line of lines) {
      const trimmed = line.trim()

      if (trimmed.startsWith('#')) continue

      if (!inBlock) {
        const headerMatch = line.match(/^((?:@[^/]+\/)?[^@\s]+)@[^:]*:$/)
        if (headerMatch) {
          currentName = headerMatch[1]
          currentVersion = ''
          currentResolved = ''
          currentIntegrity = ''
          currentDeps = []
          inBlock = true
          inDeps = false
        }
        continue
      }

      if (trimmed === '') {
        if (currentName && currentVersion) {
          entries.push({
            name: currentName,
            version: currentVersion,
            resolved: currentResolved,
            integrity: currentIntegrity,
            dependencies: currentDeps,
          })
        }
        currentName = ''
        currentVersion = ''
        currentResolved = ''
        currentIntegrity = ''
        currentDeps = []
        inBlock = false
        inDeps = false
        continue
      }

      const nextHeader = line.match(/^((?:@[^/]+\/)?[^@\s]+)@[^:]*:$/)
      if (nextHeader) {
        if (currentName && currentVersion) {
          entries.push({
            name: currentName,
            version: currentVersion,
            resolved: currentResolved,
            integrity: currentIntegrity,
            dependencies: currentDeps,
          })
        }
        currentName = nextHeader[1]
        currentVersion = ''
        currentResolved = ''
        currentIntegrity = ''
        currentDeps = []
        inDeps = false
        continue
      }

      const versionMatch = line.match(/^\s+version\s+"([^"]+)"/)
      if (versionMatch) { currentVersion = versionMatch[1]; continue }

      const resolvedMatch = line.match(/^\s+resolved\s+"([^"]+)"/)
      if (resolvedMatch) { currentResolved = resolvedMatch[1]; continue }

      const integrityMatch = line.match(/^\s+integrity\s+"([^"]+)"/)
      if (integrityMatch) { currentIntegrity = integrityMatch[1]; continue }

      if (/^\s+dependencies:$/.test(line)) { inDeps = true; continue }

      if (inDeps) {
        const depMatch = line.match(/^\s{4,}(\S+)\s+"[^"]+"/)
        if (depMatch) { currentDeps.push(depMatch[1]); continue }
      }
    }

    if (currentName && currentVersion) {
      entries.push({
        name: currentName,
        version: currentVersion,
        resolved: currentResolved,
        integrity: currentIntegrity,
        dependencies: currentDeps,
      })
    }

    return { entries, format: 'yarn' }
  }

  parse(path: string): LockfileResult {
    let content: string
    try {
      content = fs.readFileSync(path, 'utf8')
    } catch {
      return { entries: [], format: 'unknown' }
    }

    const format = this.detectFormat(content)

    switch (format) {
      case 'npm-v6':
      case 'npm-v7':
        return this.parsePackageLock(content)
      case 'yarn':
        return this.parseYarnLock(content)
      default:
        return { entries: [], format: 'unknown' }
    }
  }
}
