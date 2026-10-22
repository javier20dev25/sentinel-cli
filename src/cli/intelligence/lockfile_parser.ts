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
  format: 'npm-v6' | 'npm-v7' | 'yarn' | 'pnpm' | 'yarn-berry' | 'unknown'
}

export class LockfileParser {
  /**
   * Detects lockfiles that are recognized by filename but NOT parseable by this
   * parser. Returns a human-readable reason, or null when the file is either
   * supported or unrecognized. This lets callers report an explicit INCOMPLETE
   * status instead of a misleading "no dependencies".
   */
  detectUnsupported(filename: string, content: string): string | null {
    const base = filename.toLowerCase()
    if (base.endsWith('pnpm-lock.yaml')) {
      if (this.detectFormat(content) !== 'pnpm') {
        return 'pnpm-lock.yaml could not be parsed (unexpected or unsupported version)'
      }
      return null
    }
    if (base.endsWith('yarn.lock') && /^__metadata:/m.test(content)) {
      if (this.detectFormat(content) !== 'yarn-berry') {
        return 'Yarn Berry (v2+) lockfile could not be parsed (unexpected structure)'
      }
      return null
    }
    return null
  }

  detectFormat(content: string): string {
    const trimmed = content.trim()
    if (!trimmed) return 'unknown'

    const firstLine = trimmed.split('\n')[0].trim()

    if (firstLine.startsWith('#')) {
      // Yarn classic starts with a comment too; Berry is identified by __metadata
      if (/^__metadata:/m.test(content)) return 'yarn-berry'
      return 'yarn'
    }

    // pnpm uses YAML with a top-level lockfileVersion and importers/packages sections
    if (/^lockfileVersion:/m.test(content) || /^importers:/m.test(content)) {
      return 'pnpm'
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

  /**
   * pnpm lockfiles (lockfileVersion 5.x, 6.x, 9.x). Resolved packages live under
   * the `packages:` mapping; each key encodes `name@version` (optionally with a
   * leading slash and/or a peer-dependency suffix).
   */
  parsePnpmLock(content: string): LockfileResult {
    const entries: LockfileEntry[] = []
    const seen = new Set<string>()
    const lines = content.split(/\r?\n/)

    let inPackages = false
    let inImporters = false
    let currentPkgName = ''

    for (const line of lines) {
      if (/^packages:/.test(line) || /^snapshots:/.test(line)) { inPackages = true; inImporters = false; continue }
      if (/^importers:/.test(line)) { inImporters = true; inPackages = false; continue }
      if (/^[A-Za-z_][A-Za-z0-9_-]*:/.test(line) && !/^ {2,}/.test(line)) { inPackages = false; inImporters = false; continue }

      if (inPackages) {
        const keyMatch = line.match(/^ {2}['"]?([^'"#\s].*?)['"]?\s*:\s*$/)
        if (!keyMatch) continue
        const rawKey = keyMatch[1].trim()
        if (!rawKey) continue
        if (/^resolution|^dependencies:|^optionalDependencies:|^transitivePeerDependencies:|^version:|^specifier:/.test(rawKey)) continue
        const parsed = this.parsePnpmKey(rawKey)
        if (!parsed) continue
        const id = `${parsed.name}@${parsed.version}`
        if (seen.has(id)) continue
        seen.add(id)
        entries.push({ name: parsed.name, version: parsed.version, resolved: '', integrity: '', dependencies: [] })
        continue
      }

      if (inImporters) {
        // Workspace importers like "  .:" or "  packages/foo:"
        const importerMatch = line.match(/^ {2}(.+?):\s*$/)
        if (importerMatch && !/^ {4}/.test(line)) {
          currentPkgName = ''
          continue
        }
        // Dependency names at indent level 4 under dependencies/spec/devDependencies
        const depNameMatch = line.match(/^ {6}([@A-Za-z0-9][^:\s]*?):\s*$/)
        if (depNameMatch) {
          currentPkgName = depNameMatch[1]
          continue
        }
        if (currentPkgName) {
          const verMatch = line.match(/^\s+version:\s*['"]?([0-9][^'"\s]*)['"]?\s*$/)
          if (verMatch) {
            const id = `${currentPkgName}@${verMatch[1]}`
            if (!seen.has(id)) {
              seen.add(id)
              entries.push({ name: currentPkgName, version: verMatch[1], resolved: '', integrity: '', dependencies: [] })
            }
            currentPkgName = ''
            continue
          }
        }
      }
    }

    return { entries, format: 'pnpm' }
  }

  private parsePnpmKey(rawKey: string): { name: string; version: string } | null {
    let key = rawKey.trim().replace(/^['"]|['"]$/g, '')
    if (!key) return null
    key = key.replace(/^\//, '')
    while (/\([^()]*\)/.test(key)) { key = key.replace(/\([^()]*\)/, '') }
    key = key.split(/#/, 1)[0]
    key = key.split(/,/)[0].trim()
    if (key.includes('/node_modules/')) return null
    if (!key.includes('@')) return null

    const at = key.lastIndexOf('@')
    if (at <= 0) return null
    const name = key.slice(0, at)
    const version = key.slice(at + 1)
    if (!name || !version) return null
    if (!/^[0-9]/.test(version)) return null
    return { name, version }
  }

  /**
   * Yarn Berry (v2+) lockfiles with __metadata.
   */
  parseYarnBerry(content: string): LockfileResult {
    const entries: LockfileEntry[] = []
    const lines = content.split(/\r?\n/)

    let currentName = ''
    let currentVersion = ''
    let currentResolution = ''
    let currentDeps: string[] = []
    let inDeps = false

    const flush = () => {
      if (!currentName || !currentVersion) return
      entries.push({ name: currentName, version: currentVersion, resolved: currentResolution, integrity: '', dependencies: currentDeps })
    }

    for (const line of lines) {
      if (line.startsWith('__metadata:')) continue
      if (/^\s*#/.test(line)) continue

      const headerMatch = line.match(/^("?)([^\s].*?)\1:\s*$/)
      if (headerMatch) {
        flush()
        currentName = ''
        currentVersion = ''
        currentResolution = ''
        currentDeps = []
        inDeps = false

        const header = headerMatch[2].replace(/"/g, '')
        const descriptors = header.split(/,\s+/)
        currentName = this.descriptorToName(descriptors[0])
        continue
      }

      const versionMatch = line.match(/^\s+version:\s*"?([^"\s]+)"?\s*$/)
      if (versionMatch && !inDeps) { currentVersion = versionMatch[1]; continue }

      const resolutionMatch = line.match(/^\s+resolution:\s*"?([^"\s]+)"?\s*$/)
      if (resolutionMatch) {
        currentResolution = resolutionMatch[1]
        const parsed = this.parseBerryResolution(resolutionMatch[1])
        if (parsed) { currentName = parsed.name; currentVersion = parsed.version }
        continue
      }

      if (/^\s+dependencies:\s*$/.test(line)) { inDeps = true; continue }
      if (/^[^ \t]/.test(line) && !line.trim().startsWith('#')) { inDeps = false }

      if (inDeps) {
        const depMatch = line.match(/^\s{2,}([^\s:]+):\s*"?([^"\s]+)"?\s*$/)
        if (depMatch) { currentDeps.push(this.normalizeDepName(depMatch[1])); continue }
      }
    }

    flush()
    return { entries, format: 'yarn-berry' }
  }

  private descriptorToName(descriptor: string): string {
    let d = descriptor.replace(/^"|"$/g, '')
    const at = d.lastIndexOf('@')
    const name = at > 0 ? d.slice(0, at) : d
    return name
  }

  private parseBerryResolution(resolution: string): { name: string; version: string } | null {
    const cleaned = resolution.replace(/^"|"$/g, '')
    const m = cleaned.match(/^(.+)@(?:npm|workspace|patch|file|link):(.+)$/)
    if (!m) return null
    const name = m[1]
    let version = m[2]
    version = version.split(/[,(]/)[0].trim()
    if (!name || !/^[0-9]/.test(version)) return null
    return { name, version }
  }

  private normalizeDepName(name: string): string {
    return name.replace(/^"|"$/g, '').replace(/,\s*$/, '')
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
      case 'pnpm':
        return this.parsePnpmLock(content)
      case 'yarn-berry':
        return this.parseYarnBerry(content)
      default:
        return { entries: [], format: 'unknown' }
    }
  }
}
