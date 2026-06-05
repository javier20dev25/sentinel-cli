import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'

export interface QuarantineEntry {
  packageName: string
  version: string
  originalPath: string
  quarantinePath: string
  timestamp: number
  reason: string
  severity: string
}

export interface QuarantineStatus {
  active: boolean
  entries: QuarantineEntry[]
  quarantineDir: string
}

export class QuarantineManager {
  private sentinelDir: string
  private quarantineDir: string
  private manifestPath: string

  constructor(sentinelDir?: string) {
    const baseDir = sentinelDir || path.join(os.homedir(), '.sentinel')
    this.sentinelDir = baseDir
    this.quarantineDir = path.join(baseDir, 'quarantine')
    this.manifestPath = path.join(this.quarantineDir, 'manifest.json')
    this.ensureDirectories()
  }

  private ensureDirectories(): void {
    if (!fs.existsSync(this.sentinelDir)) {
      fs.mkdirSync(this.sentinelDir, { recursive: true })
    }
    if (!fs.existsSync(this.quarantineDir)) {
      fs.mkdirSync(this.quarantineDir, { recursive: true })
    }
  }

  private readManifest(): QuarantineEntry[] {
    try {
      if (fs.existsSync(this.manifestPath)) {
        return JSON.parse(fs.readFileSync(this.manifestPath, 'utf8'))
      }
    } catch {}
    return []
  }

  private writeManifest(entries: QuarantineEntry[]): void {
    fs.writeFileSync(this.manifestPath, JSON.stringify(entries, null, 2))
  }

  getQuarantinePath(packageName: string, version: string): string {
    if (packageName.startsWith('@')) {
      const [scope, ...rest] = packageName.split('/')
      return path.join(this.quarantineDir, scope, `${rest.join('/')}@${version}`)
    }
    return path.join(this.quarantineDir, `${packageName}@${version}`)
  }

  quarantinePackage(
    packageName: string,
    version: string,
    reason: string,
    severity: string
  ): QuarantineEntry {
    if (this.isQuarantined(packageName, version)) {
      throw new Error(`Package ${packageName}@${version} is already quarantined`)
    }

    const nmDir = path.join(process.cwd(), 'node_modules')
    const pkgDir = packageName.startsWith('@')
      ? path.join(nmDir, ...packageName.split('/'))
      : path.join(nmDir, packageName)

    if (!fs.existsSync(pkgDir)) {
      throw new Error(`Package ${packageName} not found at ${pkgDir}`)
    }

    const quarantinePath = this.getQuarantinePath(packageName, version)
    const qParentDir = path.dirname(quarantinePath)
    if (!fs.existsSync(qParentDir)) {
      fs.mkdirSync(qParentDir, { recursive: true })
    }

    fs.renameSync(pkgDir, quarantinePath)

    this.createPlaceholder(pkgDir)

    const entry: QuarantineEntry = {
      packageName,
      version,
      originalPath: pkgDir,
      quarantinePath,
      timestamp: Date.now(),
      reason,
      severity,
    }

    const entries = this.readManifest()
    entries.push(entry)
    this.writeManifest(entries)

    return entry
  }

  releasePackage(packageName: string, version: string): boolean {
    const entries = this.readManifest()
    const idx = entries.findIndex(
      (e) => e.packageName === packageName && e.version === version
    )
    if (idx === -1) return false

    const entry = entries[idx]
    const quarantinePath = entry.quarantinePath

    if (!fs.existsSync(quarantinePath)) return false

    this.removePlaceholder(entry.originalPath)

    const parentDir = path.dirname(entry.originalPath)
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true })
    }

    fs.renameSync(quarantinePath, entry.originalPath)

    entries.splice(idx, 1)
    this.writeManifest(entries)

    return true
  }

  status(): QuarantineStatus {
    const entries = this.readManifest()
    return {
      active: entries.length > 0,
      entries,
      quarantineDir: this.quarantineDir,
    }
  }

  isQuarantined(packageName: string, version?: string): boolean {
    const entries = this.readManifest()
    if (version) {
      return entries.some(
        (e) => e.packageName === packageName && e.version === version
      )
    }
    return entries.some((e) => e.packageName === packageName)
  }

  createPlaceholder(originalPath: string): void {
    if (!fs.existsSync(originalPath)) {
      fs.mkdirSync(originalPath, { recursive: true })
    }
    const placeholderContent = [
      'console.warn(\'[Sentinel] Package quarantined by Sentinel\')',
      'throw new Error(\'Package quarantined by Sentinel\')',
    ].join('\n')
    fs.writeFileSync(path.join(originalPath, 'index.js'), placeholderContent, 'utf8')
  }

  removePlaceholder(originalPath: string): void {
    if (fs.existsSync(originalPath)) {
      fs.rmSync(originalPath, { recursive: true, force: true })
    }
  }

  isEnabled(): boolean {
    const policyFile = path.join(this.sentinelDir, 'policy.json')
    try {
      if (fs.existsSync(policyFile)) {
        const policies = JSON.parse(fs.readFileSync(policyFile, 'utf8'))
        return policies.quarantine === 'on'
      }
    } catch {}
    return false
  }
}
