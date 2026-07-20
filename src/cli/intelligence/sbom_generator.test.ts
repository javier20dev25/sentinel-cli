import { describe, it, expect, vi } from 'vitest'
import { SbomGenerator, enrichSbomWithCves, CveReference } from './sbom_generator'
import { OSVVuln } from './osv_integrator'

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

describe('enrichSbomWithCves', () => {
  it('maps CVSS scores using OSVIntegrator helpers', () => {
    const sbom = {
      components: [
        { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
      ],
    }

    const osvResults = [
      {
        packageName: 'lodash',
        version: '4.17.21',
        vulnerabilities: [
          {
            id: 'GHSA-xxxx-xxxx-xxxx',
            summary: 'Prototype Pollution in lodash',
            severity: [{ type: 'CVSS_V3', score: '7.5' }],
            published: '2024-01-01',
            modified: '2024-01-02',
          } as OSVVuln,
        ],
      },
    ]

    const result = enrichSbomWithCves(sbom, osvResults)
    expect(result.components[0].vulnerabilities).toHaveLength(1)
    const vuln = result.components[0].vulnerabilities[0]
    expect(vuln.id).toBe('GHSA-xxxx-xxxx-xxxx')
    expect(vuln.severity).toBe('HIGH')
    expect(vuln.score).toBe(7.5)
    expect(vuln.summary).toBe('Prototype Pollution in lodash')
    expect(vuln.affectedVersions).toBe('4.17.21')
  })

  it('handles multiple severity entries and picks the max score', () => {
    const sbom = {
      components: [
        { name: 'pkg', version: '1.0.0', purl: 'pkg:npm/pkg@1.0.0' },
      ],
    }

    const osvResults = [
      {
        packageName: 'pkg',
        version: '1.0.0',
        vulnerabilities: [
          {
            id: 'GHSA-aaaa-bbbb-cccc',
            summary: 'Critical vuln',
            severity: [
              { type: 'CVSS_V2', score: '6.0' },
              { type: 'CVSS_V3', score: '9.3' },
            ],
            published: '2024-01-01',
            modified: '2024-01-02',
          } as OSVVuln,
        ],
      },
    ]

    const result = enrichSbomWithCves(sbom, osvResults)
    expect(result.components[0].vulnerabilities[0].score).toBe(9.3)
    expect(result.components[0].vulnerabilities[0].severity).toBe('CRITICAL')
  })

  it('falls back to database_specific.severity when no CVSS array', () => {
    const sbom = {
      components: [
        { name: 'dep', version: '2.0.0', purl: 'pkg:npm/dep@2.0.0' },
      ],
    }

    const osvResults = [
      {
        packageName: 'dep',
        version: '2.0.0',
        vulnerabilities: [
          {
            id: 'GHSA-dddd-eeee-ffff',
            summary: 'Moderate issue',
            severity: [],
            database_specific: { severity: 'MODERATE' },
            published: '2024-01-01',
            modified: '2024-01-02',
          } as OSVVuln,
        ],
      },
    ]

    const result = enrichSbomWithCves(sbom, osvResults)
    expect(result.components[0].vulnerabilities[0].severity).toBe('MEDIUM')
    expect(result.components[0].vulnerabilities[0].score).toBe(0)
  })

  it('falls back to MEDIUM when no severity info is available', () => {
    const sbom = {
      components: [
        { name: 'bare', version: '3.0.0', purl: 'pkg:npm/bare@3.0.0' },
      ],
    }

    const osvResults = [
      {
        packageName: 'bare',
        version: '3.0.0',
        vulnerabilities: [
          {
            id: 'GHSA-zzzz-yyyy-xxxx',
            summary: 'No CVSS',
            severity: [],
            published: '2024-01-01',
            modified: '2024-01-02',
          } as OSVVuln,
        ],
      },
    ]

    const result = enrichSbomWithCves(sbom, osvResults)
    expect(result.components[0].vulnerabilities[0].severity).toBe('MEDIUM')
    expect(result.components[0].vulnerabilities[0].score).toBe(0)
  })

  it('extracts affectedVersions and fixedIn from OSV affected ranges', () => {
    const sbom = {
      components: [
        { name: 'ranged-pkg', version: '1.5.0', purl: 'pkg:npm/ranged-pkg@1.5.0' },
      ],
    }

    const osvResults = [
      {
        packageName: 'ranged-pkg',
        version: '1.5.0',
        vulnerabilities: [
          {
            id: 'GHSA-rrrr-tttt-uuuu',
            summary: 'Range vuln',
            severity: [{ type: 'CVSS_V3', score: '5.0' }],
            affected: [
              {
                ranges: [
                  {
                    type: 'ECOSYSTEM',
                    events: [
                      { introduced: '1.0.0' },
                      { fixed: '1.6.0' },
                    ],
                  },
                ],
              },
            ],
            published: '2024-01-01',
            modified: '2024-01-02',
          } as OSVVuln,
        ],
      },
    ]

    const result = enrichSbomWithCves(sbom, osvResults)
    expect(result.components[0].vulnerabilities[0].affectedVersions).toBe('>= 1.0.0, < 1.6.0')
    expect(result.components[0].vulnerabilities[0].fixedIn).toBe('1.6.0')
    expect(result.components[0].vulnerabilities[0].severity).toBe('MEDIUM')
    expect(result.components[0].vulnerabilities[0].score).toBe(5.0)
  })

  it('returns unchanged sbom when osvResults is empty array', () => {
    const sbom = {
      components: [
        { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
      ],
    }

    const result = enrichSbomWithCves(sbom, [])
    expect(result.components[0].vulnerabilities).toBeUndefined()
    expect(result.components[0].name).toBe('lodash')
  })

  it('returns unchanged sbom when osvResults is null or undefined', () => {
    const sbom = {
      components: [
        { name: 'react', version: '18.0.0', purl: 'pkg:npm/react@18.0.0' },
      ],
    }

    const result1 = enrichSbomWithCves(sbom, null as any)
    expect(result1.components[0].vulnerabilities).toBeUndefined()

    const result2 = enrichSbomWithCves(sbom, undefined as any)
    expect(result2.components[0].vulnerabilities).toBeUndefined()
  })

  it('handles osvResult with no vulnerabilities (empty array)', () => {
    const sbom = {
      components: [
        { name: 'safe-pkg', version: '1.0.0', purl: 'pkg:npm/safe-pkg@1.0.0' },
      ],
    }

    const osvResults = [
      {
        packageName: 'safe-pkg',
        version: '1.0.0',
        vulnerabilities: [],
      },
    ]

    const result = enrichSbomWithCves(sbom, osvResults)
    expect(result.components[0].vulnerabilities).toBeUndefined()
  })

  it('enriches multiple components independently', () => {
    const sbom = {
      components: [
        { name: 'pkg-a', version: '1.0.0', purl: 'pkg:npm/pkg-a@1.0.0' },
        { name: 'pkg-b', version: '2.0.0', purl: 'pkg:npm/pkg-b@2.0.0' },
        { name: 'pkg-c', version: '3.0.0', purl: 'pkg:npm/pkg-c@3.0.0' },
      ],
    }

    const osvResults = [
      {
        packageName: 'pkg-a',
        version: '1.0.0',
        vulnerabilities: [
          {
            id: 'GHSA-a1',
            summary: 'Vuln A',
            severity: [{ type: 'CVSS_V3', score: '9.0' }],
            published: '2024-01-01',
            modified: '2024-01-02',
          } as OSVVuln,
        ],
      },
      {
        packageName: 'pkg-c',
        version: '3.0.0',
        vulnerabilities: [],
      },
    ]

    const result = enrichSbomWithCves(sbom, osvResults)
    expect(result.components[0].vulnerabilities).toBeDefined()
    expect(result.components[0].vulnerabilities[0].id).toBe('GHSA-a1')
    expect(result.components[1].vulnerabilities).toBeUndefined()
    expect(result.components[2].vulnerabilities).toBeUndefined()
  })

  it('does not mutate the original sbom object', () => {
    const sbom = {
      components: [
        { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
      ],
    }

    const osvResults = [
      {
        packageName: 'lodash',
        version: '4.17.21',
        vulnerabilities: [
          {
            id: 'GHSA-immutable',
            summary: 'Immutability check',
            severity: [{ type: 'CVSS_V3', score: '5.0' }],
            published: '2024-01-01',
            modified: '2024-01-02',
          } as OSVVuln,
        ],
      },
    ]

    const result = enrichSbomWithCves(sbom, osvResults)
    expect((sbom as any).components[0].vulnerabilities).toBeUndefined()
    expect(result.components[0].vulnerabilities).toBeDefined()
    expect(sbom).not.toBe(result)
  })
})
