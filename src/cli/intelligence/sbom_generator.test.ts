import { describe, it, expect, vi } from 'vitest'
import { SbomGenerator } from './sbom_generator'

vi.mock('./lockfile_parser', () => ({
  LockfileParser: class {
    parse() {
      return {
        entries: [
          { name: 'lodash', version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz', integrity: 'sha512-abc123', dependencies: [] },
          { name: 'express', version: '4.18.2', resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz', integrity: 'sha512-def456', dependencies: [] },
        ],
        format: 'npm-v7',
      }
    }
  },
}))

describe('SbomGenerator', () => {
  let generator: SbomGenerator

  beforeEach(() => {
    generator = new SbomGenerator()
  })

  describe('toPurl', () => {
    it('generates PURL for simple packages', () => {
      expect(generator.toPurl('lodash', '4.17.21')).toBe('pkg:npm/lodash@4.17.21')
    })

    it('generates PURL for scoped packages', () => {
      expect(generator.toPurl('@scope/name', '1.0.0')).toBe('pkg:npm/%40scope/name@1.0.0')
    })
  })

  describe('toCycloneDx', () => {
    it('returns valid CycloneDX JSON structure with bomFormat, specVersion, components', () => {
      const result = generator.toCycloneDx([
        { name: 'lodash', version: '4.17.21', resolved: '', integrity: '', dependencies: [] },
      ])
      expect(result.bomFormat).toBe('CycloneDX')
      expect(result.specVersion).toBe('1.5')
      expect(result.components).toHaveLength(1)
    })

    it('includes correct names, versions, and purls', () => {
      const result = generator.toCycloneDx([
        { name: 'lodash', version: '4.17.21', resolved: '', integrity: '', dependencies: [] },
        { name: '@scope/name', version: '1.0.0', resolved: '', integrity: '', dependencies: [] },
      ])
      expect(result.components[0].name).toBe('lodash')
      expect(result.components[0].version).toBe('4.17.21')
      expect(result.components[0].purl).toBe('pkg:npm/lodash@4.17.21')
      expect(result.components[1].name).toBe('@scope/name')
      expect(result.components[1].version).toBe('1.0.0')
      expect(result.components[1].purl).toBe('pkg:npm/%40scope/name@1.0.0')
    })

    it('includes integrity hash in properties when available', () => {
      const result = generator.toCycloneDx([
        { name: 'lodash', version: '4.17.21', resolved: '', integrity: 'sha512-abc123', dependencies: [] },
      ])
      expect(result.components[0].properties).toBeDefined()
      expect(result.components[0].properties).toHaveLength(1)
      expect(result.components[0].properties![0]).toEqual({ name: 'integrity', value: 'sha512-abc123' })
    })

    it('returns BOM with empty components array for empty entries', () => {
      const result = generator.toCycloneDx([])
      expect(result.bomFormat).toBe('CycloneDX')
      expect(result.specVersion).toBe('1.5')
      expect(result.components).toEqual([])
    })
  })

  describe('generate', () => {
    it('returns valid CycloneDX JSON with mock lockfile entries', () => {
      const result = generator.generate('/fake/path/package-lock.json')
      expect(result.bomFormat).toBe('CycloneDX')
      expect(result.specVersion).toBe('1.5')
      expect(result.components).toHaveLength(2)
      expect(result.components[0].name).toBe('lodash')
      expect(result.components[0].version).toBe('4.17.21')
      expect(result.components[1].name).toBe('express')
      expect(result.components[1].version).toBe('4.18.2')
    })
  })
})
