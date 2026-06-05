import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NpmAuditParser } from './npm_audit_parser'
import { execSync } from 'child_process'

vi.mock('child_process')

function makeParser(): NpmAuditParser {
  return new NpmAuditParser()
}

const sampleAuditJson = {
  auditedAt: '2026-06-05T08:00:00.000Z',
  metadata: {
    vulnerabilities: { critical: 1, high: 1, moderate: 1, low: 0 },
    dependencies: 150,
  },
  vulnerabilities: {
    lodash: [
      {
        id: 1091233,
        severity: 'critical',
        title: 'Prototype Pollution in lodash',
        via: [
          { source: 1091233, name: 'lodash', dependency: true },
          'CVE-2024-1234',
        ],
        fixAvailable: { name: 'lodash', version: '4.17.21' },
        advisory: {
          url: 'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx',
          cve: ['CVE-2024-1234'],
        },
        cvss: { score: 9.1, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' },
        range: '>=4.17.0 <4.17.21',
      },
    ],
    express: [
      {
        id: 1091234,
        severity: 'high',
        title: 'Directory Traversal in express',
        via: [{ source: 1091234, name: 'express', dependency: true }],
        fixAvailable: false,
        advisory: {
          url: 'https://github.com/advisories/GHSA-yyyy-yyyy-yyyy',
        },
        cvss: { score: 7.5, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
        range: '>=4.18.0 <4.19.0',
      },
    ],
    minimatch: [
      {
        id: 1091235,
        severity: 'moderate',
        title: 'ReDoS in minimatch',
        via: [{ source: 1091235, name: 'minimatch', dependency: true }],
        fixAvailable: { name: 'minimatch', version: '5.1.6' },
        advisory: {
          url: 'https://github.com/advisories/GHSA-zzzz-zzzz-zzzz',
        },
        cvss: { score: 5.3, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' },
        range: '>=3.0.0 <5.1.6',
      },
    ],
  },
}

describe('NpmAuditParser', () => {
  describe('parseAuditJson', () => {
    it('parses realistic npm audit output with 3 vulnerabilities', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson(sampleAuditJson)
      expect(result.vulnerabilities).toHaveLength(3)
      expect(result.auditDate).toBe('2026-06-05T08:00:00.000Z')
      expect(result.metadata.totalDependencies).toBe(150)
      expect(result.metadata.totalVulnerabilities).toBe(3)
      expect(result.metadata.critical).toBe(1)
      expect(result.metadata.high).toBe(1)
      expect(result.metadata.medium).toBe(1)
      expect(result.metadata.low).toBe(0)
    })

    it('maps severities correctly', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson(sampleAuditJson)
      const lodash = result.vulnerabilities.find(v => v.packageName === 'lodash')!
      const express = result.vulnerabilities.find(v => v.packageName === 'express')!
      const minimatch = result.vulnerabilities.find(v => v.packageName === 'minimatch')!
      expect(lodash.severity).toBe('CRITICAL')
      expect(express.severity).toBe('HIGH')
      expect(minimatch.severity).toBe('MEDIUM')
    })

    it('extracts CVE IDs from advisory URL', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson(sampleAuditJson)
      const lodash = result.vulnerabilities.find(v => v.packageName === 'lodash')!
      expect(lodash.cveId).toBe('CVE-2024-1234')
    })

    it('returns GHSA as cveId when no CVE present', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson(sampleAuditJson)
      const minimatch = result.vulnerabilities.find(v => v.packageName === 'minimatch')!
      expect(minimatch.cveId).toBe('GHSA-zzzz-zzzz-zzzz')
    })

    it('extracts CVSS scores', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson(sampleAuditJson)
      const lodash = result.vulnerabilities.find(v => v.packageName === 'lodash')!
      expect(lodash.cvssScore).toBe(9.1)
      const minimatch = result.vulnerabilities.find(v => v.packageName === 'minimatch')!
      expect(minimatch.cvssScore).toBe(5.3)
    })

    it('extracts fixAvailable info', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson(sampleAuditJson)
      const lodash = result.vulnerabilities.find(v => v.packageName === 'lodash')!
      expect(lodash.fixAvailable).toBe('lodash@4.17.21')
      const express = result.vulnerabilities.find(v => v.packageName === 'express')!
      expect(express.fixAvailable).toBeUndefined()
    })

    it('extracts dependency paths from via', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson(sampleAuditJson)
      const lodash = result.vulnerabilities.find(v => v.packageName === 'lodash')!
      expect(lodash.path).toEqual(['lodash'])
    })

    it('handles empty vulnerabilities (clean package)', () => {
      const parser = makeParser()
      const cleanJson = {
        auditedAt: '2026-06-05T08:00:00.000Z',
        metadata: {
          vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0 },
          dependencies: 150,
        },
        vulnerabilities: {},
      }
      const result = parser.parseAuditJson(cleanJson)
      expect(result.vulnerabilities).toHaveLength(0)
      expect(result.metadata.totalVulnerabilities).toBe(0)
      expect(result.metadata.totalDependencies).toBe(150)
      expect(result.metadata.critical).toBe(0)
      expect(result.metadata.high).toBe(0)
      expect(result.metadata.medium).toBe(0)
      expect(result.metadata.low).toBe(0)
    })

    it('handles null input gracefully', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson(null)
      expect(result.vulnerabilities).toHaveLength(0)
      expect(result.auditDate).toBe('')
    })

    it('handles undefined input gracefully', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson(undefined)
      expect(result.vulnerabilities).toHaveLength(0)
    })

    it('handles non-object input gracefully', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson('not an object')
      expect(result.vulnerabilities).toHaveLength(0)
    })

    it('handles missing metadata gracefully', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson({ vulnerabilities: {} })
      expect(result.vulnerabilities).toHaveLength(0)
      expect(result.metadata.totalDependencies).toBe(0)
    })
  })

  describe('runAudit', () => {
    beforeEach(() => {
      vi.mocked(execSync).mockReset()
    })

    it('parses npm audit output when no vulns found', async () => {
      const cleanOutput = JSON.stringify({
        auditedAt: '2026-06-05T08:00:00.000Z',
        metadata: {
          vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0 },
          dependencies: 100,
        },
        vulnerabilities: {},
      })
      vi.mocked(execSync).mockReturnValue(cleanOutput)
      const parser = makeParser()
      const result = await parser.runAudit()
      expect(result.vulnerabilities).toHaveLength(0)
      expect(result.metadata.totalDependencies).toBe(100)
    })

    it('handles npm audit exit code != 0 with vulns in stdout', async () => {
      const error = new Error('Command failed: npm audit --json')
      const vulnOutput = JSON.stringify(sampleAuditJson)
      ;(error as any).stdout = vulnOutput
      ;(error as any).stderr = ''
      ;(error as any).status = 1
      vi.mocked(execSync).mockImplementation(() => { throw error })
      const parser = makeParser()
      const result = await parser.runAudit()
      expect(result.vulnerabilities).toHaveLength(3)
      expect(result.metadata.totalVulnerabilities).toBe(3)
    })

    it('re-throws if stdout is missing in error', async () => {
      const error = new Error('Some other error')
      vi.mocked(execSync).mockImplementation(() => { throw error })
      const parser = makeParser()
      await expect(parser.runAudit()).rejects.toThrow('Some other error')
    })
  })

  describe('mockData', () => {
    it('returns known vulnerabilities with expected structure', () => {
      const parser = makeParser()
      const result = parser.mockData()
      expect(result.vulnerabilities).toHaveLength(3)
      expect(result.vulnerabilities[0].packageName).toBe('lodash')
      expect(result.vulnerabilities[1].packageName).toBe('express')
      expect(result.vulnerabilities[2].packageName).toBe('minimatch')
    })

    it('returns CRITICAL for lodash', () => {
      const parser = makeParser()
      const result = parser.mockData()
      expect(result.vulnerabilities[0].severity).toBe('CRITICAL')
    })

    it('returns correct metadata totals', () => {
      const parser = makeParser()
      const result = parser.mockData()
      expect(result.metadata.totalVulnerabilities).toBe(3)
      expect(result.metadata.critical).toBe(1)
      expect(result.metadata.high).toBe(1)
      expect(result.metadata.medium).toBe(1)
    })
  })

  describe('severity mapping', () => {
    it('maps critical to CRITICAL', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson({
        vulnerabilities: { test: [{ severity: 'critical', title: 'x', via: [] }] },
      })
      expect(result.vulnerabilities[0].severity).toBe('CRITICAL')
    })

    it('maps high to HIGH', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson({
        vulnerabilities: { test: [{ severity: 'high', title: 'x', via: [] }] },
      })
      expect(result.vulnerabilities[0].severity).toBe('HIGH')
    })

    it('maps moderate to MEDIUM', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson({
        vulnerabilities: { test: [{ severity: 'moderate', title: 'x', via: [] }] },
      })
      expect(result.vulnerabilities[0].severity).toBe('MEDIUM')
    })

    it('maps low to LOW', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson({
        vulnerabilities: { test: [{ severity: 'low', title: 'x', via: [] }] },
      })
      expect(result.vulnerabilities[0].severity).toBe('LOW')
    })

    it('maps info to INFO', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson({
        vulnerabilities: { test: [{ severity: 'info', title: 'x', via: [] }] },
      })
      expect(result.vulnerabilities[0].severity).toBe('INFO')
    })
  })

  describe('CVE extraction', () => {
    it('extracts CVE from advisory.cve array', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson({
        vulnerabilities: {
          test: [{
            severity: 'high',
            title: 'x',
            via: [],
            advisory: { url: 'https://github.com/advisories/GHSA-xxxx', cve: ['CVE-2024-9999'] },
          }],
        },
      })
      expect(result.vulnerabilities[0].cveId).toBe('CVE-2024-9999')
    })

    it('extracts CVE from via strings', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson({
        vulnerabilities: {
          test: [{
            severity: 'high',
            title: 'x',
            via: ['CVE-2024-8888', { source: 123, name: 'test', dependency: true }],
          }],
        },
      })
      expect(result.vulnerabilities[0].cveId).toBe('CVE-2024-8888')
    })

    it('extracts GHSA from advisory URL when no CVE', () => {
      const parser = makeParser()
      const result = parser.parseAuditJson({
        vulnerabilities: {
          test: [{
            severity: 'medium',
            title: 'x',
            via: [],
            advisory: { url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc' },
          }],
        },
      })
      expect(result.vulnerabilities[0].cveId).toBe('GHSA-aaaa-bbbb-cccc')
    })
  })
})
