import { describe, it, expect } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import { detectFormat, computeEntropy, analyzeArtifact, diffArtifacts } from './artifact-analysis'

describe('detectFormat', () => {
  it('detects ELF from magic bytes', () => {
    const elfBytes = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00])
    const tmp = path.join(__dirname, '__fixtures__')
    fs.mkdirSync(tmp, { recursive: true })
    const fp = path.join(tmp, 'test.elf')
    fs.writeFileSync(fp, elfBytes)

    const result = detectFormat(fp)
    expect(result.format).toBe('elf')

    fs.unlinkSync(fp)
  })

  it('detects PE from magic bytes', () => {
    const peBytes = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00])
    const tmp = path.join(__dirname, '__fixtures__')
    fs.mkdirSync(tmp, { recursive: true })
    const fp = path.join(tmp, 'test.exe')
    fs.writeFileSync(fp, peBytes)

    const result = detectFormat(fp)
    expect(result.format).toBe('pe')

    fs.unlinkSync(fp)
  })

  it('returns unknown for random bytes', () => {
    const tmp = path.join(__dirname, '__fixtures__')
    fs.mkdirSync(tmp, { recursive: true })
    const fp = path.join(tmp, 'test.bin')
    fs.writeFileSync(fp, Buffer.from([0x00, 0x01, 0x02, 0x03]))

    const result = detectFormat(fp)
    expect(result.format).toBe('unknown')

    fs.unlinkSync(fp)
  })
})

describe('computeEntropy', () => {
  it('returns 0 for empty data', () => {
    expect(computeEntropy(Buffer.from([]))).toBe(0)
  })

  it('returns 0 for uniform data', () => {
    expect(computeEntropy(Buffer.from([0x00, 0x00, 0x00, 0x00]))).toBe(0)
  })

  it('returns 8 for fully random data', () => {
    const rand = Buffer.alloc(256)
    for (let i = 0; i < 256; i++) rand[i] = i
    expect(computeEntropy(rand)).toBeCloseTo(8, 0)
  })

  it('returns intermediate value for mixed data', () => {
    // half zeros, half sequential
    const buf = Buffer.alloc(512)
    for (let i = 0; i < 256; i++) buf[i] = 0
    for (let i = 256; i < 512; i++) buf[i] = i - 256
    const e = computeEntropy(buf)
    expect(e).toBeGreaterThan(0)
    expect(e).toBeLessThan(8)
  })
})

describe('diffArtifacts', () => {
  it('returns empty diff for identical analysis', () => {
    const tmp = path.join(__dirname, '__fixtures__')
    fs.mkdirSync(tmp, { recursive: true })
    const fp = path.join(tmp, 'diff_test.bin')
    fs.writeFileSync(fp, Buffer.from([0x00, 0x01, 0x02, 0x03]))

    const a1 = analyzeArtifact(fp)
    const a2 = analyzeArtifact(fp)
    const diff = diffArtifacts(a1, a2)

    expect(diff.addedSections).toHaveLength(0)
    expect(diff.removedSections).toHaveLength(0)
    expect(diff.addedImports).toHaveLength(0)
    expect(diff.findings).toHaveLength(0)

    fs.unlinkSync(fp)
  })
})

describe('analyzeArtifact', () => {
  it('handles non-existent files gracefully', () => {
    const analysis = analyzeArtifact('/nonexistent/file.bin')
    expect(analysis.format).toBe('unknown')
    expect(analysis.sha256).toBe('')
  })

  it('extracts ELF info if readelf available', () => {
    const tmp = path.join(__dirname, '__fixtures__')
    fs.mkdirSync(tmp, { recursive: true })

    // Create minimal ELF
    const elfBuf = Buffer.alloc(128)
    elfBuf[0] = 0x7f; elfBuf[1] = 0x45; elfBuf[2] = 0x4c; elfBuf[3] = 0x46 // ELF magic
    elfBuf[4] = 0x02 // 64-bit
    elfBuf[5] = 0x01 // little endian

    const fp = path.join(tmp, 'minimal.elf')
    fs.writeFileSync(fp, elfBuf)

    const analysis = analyzeArtifact(fp)
    expect(analysis.format).toBe('elf')
    expect(analysis.size).toBe(128)
    expect(analysis.sha256).toBeTruthy()

    fs.unlinkSync(fp)
  })
})
