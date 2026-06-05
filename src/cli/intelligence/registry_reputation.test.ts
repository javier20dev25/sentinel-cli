import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockExecSync = vi.hoisted(() => vi.fn())

vi.mock('child_process', () => ({
  execSync: mockExecSync,
}))

import { RegistryReputation } from './registry_reputation'

describe('RegistryReputation', () => {
  let reputation: RegistryReputation

  beforeEach(() => {
    vi.clearAllMocks()
    reputation = new RegistryReputation()
  })

  describe('score', () => {
    it('returns SUSPICIOUS for new package (< 30 days, 1 maintainer, few versions)', async () => {
      mockExecSync.mockReturnValue(JSON.stringify({
        name: 'new-pkg',
        description: 'A utility package for data processing',
        'dist-tags': { latest: '1.0.2' },
        versions: {
          '1.0.0': { name: 'new-pkg', version: '1.0.0' },
          '1.0.1': { name: 'new-pkg', version: '1.0.1' },
          '1.0.2': { name: 'new-pkg', version: '1.0.2' },
        },
        maintainers: [{ name: 'dev1', email: 'dev1@example.com' }],
        time: { created: new Date(Date.now() - 10 * 86400000).toISOString() },
        homepage: 'https://github.com/dev1/new-pkg',
      }))

      const result = await reputation.score('new-pkg')
      expect(result.packageName).toBe('new-pkg')
      expect(result.version).toBe('1.0.2')
      expect(result.label).toBe('SUSPICIOUS')
      expect(result.score).toBeLessThan(0)
      expect(result.score).toBeGreaterThanOrEqual(-30)
    })

    it('returns TRUSTED for established package (> 365 days, 10 maintainers, many versions)', async () => {
      mockExecSync.mockReturnValue(JSON.stringify({
        name: 'est-pkg',
        description: 'A well-established and maintained package for production use',
        'dist-tags': { latest: '10.0.0' },
        versions: Object.fromEntries(
          Array.from({ length: 100 }, (_, i) => [
            `${i + 1}.0.0`,
            { name: 'est-pkg', version: `${i + 1}.0.0` },
          ])
        ),
        maintainers: Array.from({ length: 10 }, (_, i) => ({
          name: `maintainer${i + 1}`,
          email: `m${i + 1}@example.com`,
        })),
        time: { created: new Date(Date.now() - 730 * 86400000).toISOString() },
        homepage: 'https://github.com/org/est-pkg',
      }))

      const result = await reputation.score('est-pkg')
      expect(result.packageName).toBe('est-pkg')
      expect(result.version).toBe('10.0.0')
      expect(result.label).toBe('TRUSTED')
      expect(result.score).toBeGreaterThanOrEqual(50)
    })

    it('returns SUSPICIOUS with -30 deprecation factor for deprecated package', async () => {
      mockExecSync.mockReturnValue(JSON.stringify({
        name: 'deprecated-pkg',
        description: 'This package is deprecated',
        'dist-tags': { latest: '2.0.0' },
        versions: {
          '1.0.0': { name: 'deprecated-pkg', version: '1.0.0' },
          '2.0.0': { name: 'deprecated-pkg', version: '2.0.0', deprecated: 'Use new-pkg instead' },
        },
        maintainers: [
          { name: 'dev1', email: 'dev1@example.com' },
          { name: 'dev2', email: 'dev2@example.com' },
        ],
        time: { created: new Date(Date.now() - 200 * 86400000).toISOString() },
        homepage: 'https://github.com/dev1/deprecated-pkg',
      }))

      const result = await reputation.score('deprecated-pkg')
      expect(result.label).toBe('SUSPICIOUS')
      expect(result.factors.some(f => f.name === 'deprecation' && f.impact === -30)).toBe(true)
    })

    it('returns SUSPICIOUS with description factor when description is missing', async () => {
      mockExecSync.mockReturnValue(JSON.stringify({
        name: 'no-desc-pkg',
        description: '',
        'dist-tags': { latest: '1.0.5' },
        versions: {
          '1.0.0': { name: 'no-desc-pkg', version: '1.0.0' },
          '1.0.1': { name: 'no-desc-pkg', version: '1.0.1' },
          '1.0.2': { name: 'no-desc-pkg', version: '1.0.2' },
          '1.0.3': { name: 'no-desc-pkg', version: '1.0.3' },
          '1.0.4': { name: 'no-desc-pkg', version: '1.0.4' },
          '1.0.5': { name: 'no-desc-pkg', version: '1.0.5' },
        },
        maintainers: [{ name: 'lonely-dev' }],
        time: { created: new Date(Date.now() - 20 * 86400000).toISOString() },
        homepage: undefined,
      }))

      const result = await reputation.score('no-desc-pkg')
      expect(result.label).toBe('SUSPICIOUS')
      expect(result.factors.some(f => f.name === 'description' && f.impact === -5)).toBe(true)
    })

    it('returns NEUTRAL with 0 score for package not found', async () => {
      mockExecSync.mockImplementation(() => {
        throw new Error('npm ERR! code E404\nnpm ERR! 404 Not Found')
      })

      const result = await reputation.score('nonexistent-package-that-does-not-exist')
      expect(result.packageName).toBe('nonexistent-package-that-does-not-exist')
      expect(result.score).toBe(0)
      expect(result.label).toBe('NEUTRAL')
      expect(result.version).toBe('unknown')
    })
  })

  describe('getLabel', () => {
    it('returns TRUSTED for score >= 50', () => {
      expect(reputation.getLabel(50)).toBe('TRUSTED')
      expect(reputation.getLabel(100)).toBe('TRUSTED')
    })

    it('returns NEUTRAL for score >= 0 and < 50', () => {
      expect(reputation.getLabel(49)).toBe('NEUTRAL')
      expect(reputation.getLabel(0)).toBe('NEUTRAL')
      expect(reputation.getLabel(20)).toBe('NEUTRAL')
    })

    it('returns SUSPICIOUS for score >= -30 and < 0', () => {
      expect(reputation.getLabel(-1)).toBe('SUSPICIOUS')
      expect(reputation.getLabel(-30)).toBe('SUSPICIOUS')
      expect(reputation.getLabel(-15)).toBe('SUSPICIOUS')
    })

    it('returns MALICIOUS for score < -30', () => {
      expect(reputation.getLabel(-31)).toBe('MALICIOUS')
      expect(reputation.getLabel(-100)).toBe('MALICIOUS')
    })
  })
})
