import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { QuarantineManager } from './quarantine'

describe('QuarantineManager', () => {
  let testDir: string
  let sentinelDir: string
  let nmDir: string
  let manager: QuarantineManager

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-quarantine-'))
    sentinelDir = path.join(testDir, '.sentinel')
    nmDir = path.join(testDir, 'node_modules')
    fs.mkdirSync(nmDir, { recursive: true })

    vi.spyOn(process, 'cwd').mockReturnValue(testDir)

    manager = new QuarantineManager(sentinelDir)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    try { fs.rmSync(testDir, { recursive: true, force: true }) } catch {}
  })

  function createPkg(name: string, version: string) {
    const pkgDir = name.startsWith('@')
      ? path.join(nmDir, ...name.split('/'))
      : path.join(nmDir, name)
    fs.mkdirSync(pkgDir, { recursive: true })
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify({ name, version })
    )
    fs.writeFileSync(path.join(pkgDir, 'index.js'), 'module.exports = { hello: "world" }')
    return pkgDir
  }

  it('quarantinePackage moves package to quarantine dir', () => {
    createPkg('test-pkg', '1.0.0')
    const entry = manager.quarantinePackage('test-pkg', '1.0.0', 'suspicious activity', 'HIGH')

    expect(entry.packageName).toBe('test-pkg')
    expect(entry.version).toBe('1.0.0')
    expect(entry.reason).toBe('suspicious activity')

    const originalPkgDir = path.join(nmDir, 'test-pkg')
    expect(fs.existsSync(originalPkgDir)).toBe(true)
    const placeholderFile = path.join(originalPkgDir, 'index.js')
    expect(fs.existsSync(placeholderFile)).toBe(true)
    const content = fs.readFileSync(placeholderFile, 'utf8')
    expect(content).toContain('Package quarantined by Sentinel')

    expect(fs.existsSync(entry.quarantinePath)).toBe(true)
    expect(fs.existsSync(path.join(entry.quarantinePath, 'package.json'))).toBe(true)
  })

  it('releasePackage restores package from quarantine', () => {
    createPkg('test-pkg', '1.0.0')
    const entry = manager.quarantinePackage('test-pkg', '1.0.0', 'suspicious', 'HIGH')

    const result = manager.releasePackage('test-pkg', '1.0.0')
    expect(result).toBe(true)

    const originalPkgDir = path.join(nmDir, 'test-pkg')
    expect(fs.existsSync(originalPkgDir)).toBe(true)
    expect(fs.existsSync(path.join(originalPkgDir, 'package.json'))).toBe(true)
    const indexContent = fs.readFileSync(path.join(originalPkgDir, 'index.js'), 'utf8')
    expect(indexContent).toContain('hello')
    expect(indexContent).not.toContain('quarantined')

    expect(fs.existsSync(entry.quarantinePath)).toBe(false)
  })

  it('isQuarantined returns true for quarantined package', () => {
    createPkg('test-pkg', '1.0.0')
    manager.quarantinePackage('test-pkg', '1.0.0', 'suspicious', 'HIGH')
    expect(manager.isQuarantined('test-pkg', '1.0.0')).toBe(true)
  })

  it('isQuarantined returns false for non-quarantined package', () => {
    expect(manager.isQuarantined('nonexistent', '1.0.0')).toBe(false)
  })

  it('status returns correct entry count', () => {
    createPkg('pkg-a', '1.0.0')
    createPkg('pkg-b', '2.0.0')
    manager.quarantinePackage('pkg-a', '1.0.0', 'reason-a', 'LOW')
    manager.quarantinePackage('pkg-b', '2.0.0', 'reason-b', 'CRITICAL')

    const status = manager.status()
    expect(status.active).toBe(true)
    expect(status.entries).toHaveLength(2)

    manager.releasePackage('pkg-a', '1.0.0')
    expect(manager.status().entries).toHaveLength(1)
  })

  it('quarantinePackage on non-existent node_modules handles gracefully', () => {
    expect(() => {
      manager.quarantinePackage('ghost-pkg', '1.0.0', 'test', 'LOW')
    }).toThrow('ghost-pkg not found')
  })

  it('releasePackage on non-quarantined package returns false', () => {
    expect(manager.releasePackage('never-quarantined', '1.0.0')).toBe(false)
  })

  it('isEnabled reads from policy.json', () => {
    expect(manager.isEnabled()).toBe(false)

    const policyFile = path.join(sentinelDir, 'policy.json')
    fs.writeFileSync(policyFile, JSON.stringify({ quarantine: 'off' }))
    expect(manager.isEnabled()).toBe(false)

    fs.writeFileSync(policyFile, JSON.stringify({ quarantine: 'on' }))
    expect(manager.isEnabled()).toBe(true)
  })
})
