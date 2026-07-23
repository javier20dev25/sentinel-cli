import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import {
  categorizeFile,
  scanBuildInputs,
  computeInputFingerprint,
  computeInputStability,
  diffInputs,
  buildInputIdentity,
  renderInputChanges,
  computeToolchainPurity,
  buildInputFromFile,
  captureScriptIdentity,
  isNonInputDir,
  isNonInputFile,
} from './build-input-identity'
import { BuildInput, InputChange } from './build-types'

describe('Build Input Identity', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-input-'))
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  describe('categorizeFile', () => {
    it('classifies Makefile as build_system', () => {
      const f = path.join(tmpDir, 'Makefile')
      fs.writeFileSync(f, 'all:')
      expect(categorizeFile(f, tmpDir)).toBe('build_system')
    })

    it('classifies package.json as language_config', () => {
      const f = path.join(tmpDir, 'package.json')
      fs.writeFileSync(f, '{}')
      expect(categorizeFile(f, tmpDir)).toBe('language_config')
    })

    it('classifies .github/workflows/ci.yml as ci_config', () => {
      const dir = path.join(tmpDir, '.github', 'workflows')
      fs.mkdirSync(dir, { recursive: true })
      const f = path.join(dir, 'ci.yml')
      fs.writeFileSync(f, 'name: CI')
      expect(categorizeFile(f, tmpDir)).toBe('ci_config')
    })

    it('classifies .sh files as shell_script', () => {
      const f = path.join(tmpDir, 'build.sh')
      fs.writeFileSync(f, '#!/bin/bash')
      expect(categorizeFile(f, tmpDir)).toBe('shell_script')
    })

    it('classifies .ps1 files as shell_script', () => {
      const f = path.join(tmpDir, 'deploy.ps1')
      fs.writeFileSync(f, 'Write-Host')
      expect(categorizeFile(f, tmpDir)).toBe('shell_script')
    })

    it('returns null for non-input files (README.md)', () => {
      const f = path.join(tmpDir, 'README.md')
      fs.writeFileSync(f, '# Project')
      expect(categorizeFile(f, tmpDir)).toBeNull()
    })

    it('returns null for unknown file types', () => {
      const f = path.join(tmpDir, 'random.txt')
      fs.writeFileSync(f, 'data')
      expect(categorizeFile(f, tmpDir)).toBeNull()
    })
  })

  describe('isNonInputDir', () => {
    it('node_modules is non-input', () => {
      expect(isNonInputDir('node_modules')).toBe(true)
    })
    it('.git is non-input', () => {
      expect(isNonInputDir('.git')).toBe(true)
    })
    it('docs is non-input', () => {
      expect(isNonInputDir('docs')).toBe(true)
    })
    it('src is input', () => {
      expect(isNonInputDir('src')).toBe(false)
    })
  })

  describe('isNonInputFile', () => {
    it('README is non-input', () => {
      expect(isNonInputFile('README')).toBe(true)
    })
    it('LICENSE is non-input', () => {
      expect(isNonInputFile('LICENSE')).toBe(true)
    })
    it('Makefile is input', () => {
      expect(isNonInputFile('Makefile')).toBe(false)
    })
  })

  describe('buildInputFromFile', () => {
    it('returns BuildInput with sha256 for a file', () => {
      const f = path.join(tmpDir, 'Makefile')
      fs.writeFileSync(f, 'all:\n\techo hello')
      const input = buildInputFromFile(f, 'Makefile', 'build_system')
      expect(input).not.toBeNull()
      expect(input!.sha256.length).toBe(64)
      expect(input!.filePath).toBe('Makefile')
      expect(input!.size).toBeGreaterThan(0)
      expect(input!.permissions.length).toBeGreaterThan(0)
      expect(typeof input!.mtime).toBe('number')
    })

    it('returns null for non-existent file gracefully', () => {
      const input = buildInputFromFile('/nonexistent/file', 'nope', 'build_system')
      expect(input).toBeNull()
    })
  })

  describe('scanBuildInputs', () => {
    it('finds Makefile and package.json in workspace', () => {
      fs.writeFileSync(path.join(tmpDir, 'Makefile'), 'all:')
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{}')
      fs.writeFileSync(path.join(tmpDir, 'README.md'), '# readme')
      const inputs = scanBuildInputs(tmpDir)
      const names = inputs.map(i => i.filePath)
      expect(names).toContain('Makefile')
      expect(names).toContain('package.json')
      expect(names).not.toContain('README.md')
    })

    it('finds scripts in subdirectories but skips node_modules', () => {
      fs.mkdirSync(path.join(tmpDir, 'src', 'scripts'), { recursive: true })
      fs.writeFileSync(path.join(tmpDir, 'src', 'scripts', 'build.sh'), '#!/bin/bash')
      fs.writeFileSync(path.join(tmpDir, 'Makefile'), 'all:')
      const inputs = scanBuildInputs(tmpDir)
      const names = inputs.map(i => i.filePath)
      expect(names).toContain('Makefile')
      expect(names).toContain('src/scripts/build.sh')
    })

    it('skips node_modules directory', () => {
      fs.mkdirSync(path.join(tmpDir, 'node_modules', 'pkg'), { recursive: true })
      fs.writeFileSync(path.join(tmpDir, 'node_modules', 'pkg', 'package.json'), '{}')
      const inputs = scanBuildInputs(tmpDir)
      const names = inputs.map(i => i.filePath)
      expect(names).not.toContain('node_modules/pkg/package.json')
    })

    it('returns empty for empty directory', () => {
      expect(scanBuildInputs(tmpDir)).toEqual([])
    })
  })

  describe('computeInputFingerprint', () => {
    it('produces deterministic hash for same inputs', () => {
      const inputs: BuildInput[] = [
        {
          filePath: 'Makefile', category: 'build_system',
          sha256: 'a'.repeat(64), size: 100, mtime: 1000,
          permissions: '644', owner: '', symlinkTarget: null,
          realPath: '/tmp/Makefile', encoding: 'utf-8',
        },
        {
          filePath: 'Cargo.toml', category: 'language_config',
          sha256: 'b'.repeat(64), size: 200, mtime: 2000,
          permissions: '644', owner: '', symlinkTarget: null,
          realPath: '/tmp/Cargo.toml', encoding: 'utf-8',
        },
      ]
      const fp1 = computeInputFingerprint(inputs)
      const fp2 = computeInputFingerprint([...inputs].reverse())
      expect(fp1).toBe(fp2)
      expect(fp1.length).toBe(64)
    })

    it('produces different hash for different content', () => {
      const a: BuildInput = {
        filePath: 'Makefile', category: 'build_system',
        sha256: 'a'.repeat(64), size: 100, mtime: 1000,
        permissions: '644', owner: '', symlinkTarget: null,
        realPath: '/tmp/Makefile', encoding: 'utf-8',
      }
      const b: BuildInput = { ...a, sha256: 'b'.repeat(64) }
      expect(computeInputFingerprint([a])).not.toBe(computeInputFingerprint([b]))
    })
  })

  describe('computeInputStability', () => {
    it('returns 100 for identical counts', () => {
      expect(computeInputStability(10, 10)).toBe(100)
    })
    it('returns 50 when half removed', () => {
      expect(computeInputStability(5, 10)).toBe(50)
    })
    it('returns 0 when previous was 0 and current is 0', () => {
      expect(computeInputStability(0, 0)).toBe(100)
    })
    it('returns 200 when doubled', () => {
      expect(computeInputStability(10, 5)).toBe(200)
    })
  })

  describe('diffInputs', () => {
    it('detects new input', () => {
      const prev: BuildInput[] = []
      const curr = [makeInput('Makefile', 'aaa')]
      const changes = diffInputs(prev, curr)
      expect(changes.length).toBe(1)
      expect(changes[0].changeType).toBe('new')
    })

    it('detects removed input', () => {
      const prev = [makeInput('Makefile', 'aaa')]
      const curr: BuildInput[] = []
      const changes = diffInputs(prev, curr)
      expect(changes.length).toBe(1)
      expect(changes[0].changeType).toBe('removed')
    })

    it('detects modified input', () => {
      const prev = [makeInput('Makefile', 'aaa')]
      const curr = [makeInput('Makefile', 'bbb')]
      const changes = diffInputs(prev, curr)
      expect(changes.length).toBe(1)
      expect(changes[0].changeType).toBe('modified')
      expect(changes[0].previousSha256).toBe('aaa')
    })

    it('detects permission change', () => {
      const prev = [makeInput('script.sh', 'aaa', '755')]
      const curr = [makeInput('script.sh', 'aaa', '644')]
      const changes = diffInputs(prev, curr)
      expect(changes.some(c => c.changeType === 'permission_changed')).toBe(true)
    })

    it('detects multiple changes', () => {
      const prev = [
        makeInput('A', 'a1'),
        makeInput('B', 'b1'),
        makeInput('C', 'c1'),
      ]
      const curr = [
        makeInput('A', 'a2'),
        makeInput('B', 'b1'),
        makeInput('D', 'd1'),
      ]
      const changes = diffInputs(prev, curr)
      expect(changes.some(c => c.changeType === 'modified' && c.input.filePath === 'A')).toBe(true)
      expect(changes.some(c => c.changeType === 'removed' && c.input.filePath === 'C')).toBe(true)
      expect(changes.some(c => c.changeType === 'new' && c.input.filePath === 'D')).toBe(true)
    })

    it('returns empty for identical inputs', () => {
      const list = [makeInput('M', 'aaa')]
      expect(diffInputs(list, list)).toEqual([])
    })
  })

  describe('buildInputIdentity', () => {
    it('returns identity with inputs from directory', () => {
      fs.writeFileSync(path.join(tmpDir, 'Makefile'), 'all:')
      const identity = buildInputIdentity(tmpDir)
      expect(identity.totalInputs).toBe(1)
      expect(identity.inputFingerprint.length).toBe(64)
      expect(Array.isArray(identity.inputs)).toBe(true)
      expect(identity.changedInputs).toEqual([])
      expect(identity.inputStability).toBeNull()
    })

    it('detects changes when prevInputs provided', () => {
      fs.writeFileSync(path.join(tmpDir, 'Makefile'), 'all:')
      const prev = scanBuildInputs(tmpDir)
      fs.writeFileSync(path.join(tmpDir, 'Cargo.toml'), '[package]')
      const identity = buildInputIdentity(tmpDir, prev)
      expect(identity.changedInputs.length).toBeGreaterThan(0)
      expect(identity.inputStability).not.toBeNull()
    })
  })

  describe('computeToolchainPurity', () => {
    it('returns 100 when all expected tools present', () => {
      expect(computeToolchainPurity(['gcc', 'ld', 'make'], ['gcc', 'ld', 'make', 'python'])).toBe(100)
    })
    it('returns 0 when no expected tools present', () => {
      expect(computeToolchainPurity(['gcc', 'ld'], ['python', 'node'])).toBe(0)
    })
    it('returns proportional when half present', () => {
      expect(computeToolchainPurity(['gcc', 'ld'], ['gcc', 'python'])).toBe(50)
    })
    it('handles empty sets', () => {
      expect(computeToolchainPurity([], [])).toBe(100)
      expect(computeToolchainPurity([], ['gcc'])).toBe(0)
    })
  })

  describe('renderInputChanges', () => {
    it('renders no changes message when empty', () => {
      const lines = renderInputChanges([])
      expect(lines.some(l => l.includes('No input changes'))).toBe(true)
    })

    it('renders changes with icons', () => {
      const changes: InputChange[] = [
        { input: makeInput('Makefile', 'aaa'), changeType: 'modified', previousSha256: 'bbb' },
        { input: makeInput('build.sh', 'ccc'), changeType: 'new' },
      ]
      const lines = renderInputChanges(changes)
      expect(lines.some(l => l.includes('[modified]'))).toBe(true)
      expect(lines.some(l => l.includes('[new]'))).toBe(true)
      expect(lines.some(l => l.includes('Makefile'))).toBe(true)
    })
  })

  describe('captureScriptIdentity', () => {
    it('returns null for unknown command', () => {
      const result = captureScriptIdentity(999999, '')
      expect(result).toBeNull()
    })
  })

  describe('real-world build input detection', () => {
    it('detects Cargo.toml, build.rs, go.mod, package.json', () => {
      // Rust
      fs.mkdirSync(path.join(tmpDir, 'rust-project'), { recursive: true })
      fs.writeFileSync(path.join(tmpDir, 'rust-project', 'Cargo.toml'), '[package]')
      fs.writeFileSync(path.join(tmpDir, 'rust-project', 'build.rs'), 'fn main() {}')

      // Go
      fs.mkdirSync(path.join(tmpDir, 'go-project'), { recursive: true })
      fs.writeFileSync(path.join(tmpDir, 'go-project', 'go.mod'), 'module example')

      // Node
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"test"}')
      fs.writeFileSync(path.join(tmpDir, 'Makefile'), 'all:')

      // Should NOT find these
      fs.writeFileSync(path.join(tmpDir, 'README.md'), '# Project')
      fs.mkdirSync(path.join(tmpDir, 'docs'), { recursive: true })
      fs.writeFileSync(path.join(tmpDir, 'docs', 'guide.md'), '# Guide')

      const inputs = scanBuildInputs(tmpDir)
      const paths = inputs.map(i => i.filePath)

      expect(paths).toContain('Makefile')
      expect(paths).toContain('package.json')
      expect(paths).not.toContain('README.md')
      expect(paths).not.toContain('docs/guide.md')
    })
  })
})

function makeInput(filePath: string, sha256: string, permissions = '644'): BuildInput {
  return {
    filePath, category: 'build_system',
    sha256, size: 100, mtime: 1000,
    permissions, owner: '', symlinkTarget: null,
    realPath: '/tmp/' + filePath, encoding: 'utf-8',
  }
}
