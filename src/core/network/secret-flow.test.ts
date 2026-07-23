import { describe, it, expect } from 'vitest'
import {
  scanFileForSecrets,
  scanEnvForSecrets,
  buildSecretFlowChains,
  computeHermeticScore,
  computeReproducibilityScore,
  renderSecretFlowChains,
  renderHermeticScore,
  renderReproducibilityScore,
} from './secret-flow'
import { SecretAccess, BuildProcessEvent, BuildNetEvent } from './build-types'

const FIXTURE_DIR = __dirname + '/__fixtures__'

describe('secret-flow', () => {
  describe('computeHermeticScore', () => {
    it('returns 100 for perfect hermetic build', () => {
      expect(computeHermeticScore(10, 0, 0, 5, 0, 0, 0, 0)).toBe(100)
    })

    it('deducts for network activity', () => {
      const score = computeHermeticScore(10, 5, 0, 5, 0, 0, 0, 0)
      expect(score).toBeLessThan(100)
      expect(score).toBeGreaterThanOrEqual(70)
    })

    it('deducts for unknown tools', () => {
      const score = computeHermeticScore(10, 0, 4, 5, 0, 0, 0, 0)
      expect(score).toBe(80)
    })

    it('deducts for path changes', () => {
      const score = computeHermeticScore(10, 0, 0, 5, 3, 0, 0, 0)
      expect(score).toBe(85)
    })

    it('deducts for contract violations', () => {
      const score = computeHermeticScore(10, 0, 0, 5, 0, 3, 0, 0)
      expect(score).toBe(80)
    })

    it('deducts for ephemeral processes', () => {
      const score = computeHermeticScore(10, 0, 0, 5, 0, 0, 5, 0)
      expect(score).toBe(90)
    })

    it('deducts for secrets found', () => {
      const score = computeHermeticScore(10, 0, 0, 5, 0, 0, 0, 2)
      expect(score).toBe(70)
    })

    it('clamps to 0', () => {
      const score = computeHermeticScore(10, 10, 10, 5, 10, 10, 10, 10)
      expect(score).toBe(0)
    })

    it('clamps to 100', () => {
      expect(computeHermeticScore(0, 0, 0, 0, 0, 0, 0, 0)).toBe(100)
    })
  })

  describe('computeReproducibilityScore', () => {
    it('returns 0 when no previous record', () => {
      const result = computeReproducibilityScore('abc', null, [], null)
      expect(result.score).toBe(0)
      expect(result.sameInputs).toBe(true)
    })

    it('returns 100 when everything matches', () => {
      const result = computeReproducibilityScore('abc', 'abc', [{ sha256: 'x' }], [{ sha256: 'x' }])
      expect(result.score).toBe(100)
    })

    it('deducts for different inputs', () => {
      const result = computeReproducibilityScore('abc', 'def', [{ sha256: 'x' }], [{ sha256: 'x' }])
      expect(result.score).toBe(70)
      expect(result.sameInputs).toBe(false)
    })

    it('deducts for different artifacts', () => {
      const result = computeReproducibilityScore('abc', 'abc', [{ sha256: 'x' }], [{ sha256: 'y' }])
      expect(result.score).toBe(60)
      expect(result.sameArtifacts).toBe(false)
    })

    it('deducts for both different', () => {
      const result = computeReproducibilityScore('abc', 'def', [{ sha256: 'x' }], [{ sha256: 'y' }])
      expect(result.score).toBe(30)
    })
  })

  describe('scanEnvForSecrets', () => {
    it('detects known sensitive env vars', () => {
      const secrets = scanEnvForSecrets({ AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' })
      expect(secrets.length).toBe(1)
      expect(secrets[0].type).toBe('env_variable')
      expect(secrets[0].severity).toBe('critical')
    })

    it('ignores non-sensitive env vars', () => {
      const secrets = scanEnvForSecrets({ PATH: '/usr/bin', HOME: '/root' })
      expect(secrets.length).toBe(0)
    })

    it('detects multiple sensitive vars', () => {
      const secrets = scanEnvForSecrets({
        AWS_SECRET_ACCESS_KEY: 'key1',
        GITHUB_TOKEN: 'ghp_token',
        PATH: '/usr/bin',
      })
      expect(secrets.length).toBe(2)
    })
  })

  describe('buildSecretFlowChains', () => {
    it('returns empty for no secrets', () => {
      const chains = buildSecretFlowChains([], [], [])
      expect(chains.length).toBe(0)
    })

    it('builds chain from secret access to network', () => {
      const secrets: SecretAccess[] = [{
        type: 'github_token', severity: 'critical',
        filePath: '.env', match: 'ghp_12345', line: 1,
        context: '', snippet: '', sha256: 'abc',
        pid: 100, processName: 'node', timestamp: 1000,
      }]
      const processes: BuildProcessEvent[] = [{
        pid: 100, name: 'node', cmdline: 'node build.js',
        ppid: 1, pname: 'bash', timestamp: 500,
      }]
      const network: BuildNetEvent[] = [{
        type: 'tcp', host: 'example.com', port: 443, timestamp: 2000,
      }]

      const chains = buildSecretFlowChains(secrets, processes, network)
      expect(chains.length).toBe(1)
      expect(chains[0].processName).toBe('node')
      expect(chains[0].hasExfilRisk).toBe(true)
      expect(chains[0].severity).toBe('critical')
    })

    it('marks no exfil risk when no network after secret', () => {
      const secrets: SecretAccess[] = [{
        type: 'generic_secret_assignment', severity: 'medium',
        filePath: 'config.json', match: 'password = "x"', line: 1,
        context: '', snippet: '', sha256: 'abc',
        pid: 100, processName: 'node', timestamp: 2000,
      }]
      const processes: BuildProcessEvent[] = [{
        pid: 100, name: 'node', cmdline: 'node build.js',
        ppid: 1, pname: 'bash', timestamp: 500,
      }]
      const network: BuildNetEvent[] = [{
        type: 'tcp', host: 'example.com', port: 443, timestamp: 1000,
      }]

      const chains = buildSecretFlowChains(secrets, processes, network)
      expect(chains.length).toBe(1)
      expect(chains[0].hasExfilRisk).toBe(false)
    })
  })

  describe('renderSecretFlowChains', () => {
    it('returns empty message when no chains', () => {
      const result = renderSecretFlowChains([])
      expect(result[0]).toBe('No secret flows detected')
    })
  })

  describe('renderHermeticScore', () => {
    it('renders score bar', () => {
      const result = renderHermeticScore(100)
      expect(result.some(l => l.includes('100/100'))).toBe(true)
    })
  })

  describe('renderReproducibilityScore', () => {
    it('renders correctly', () => {
      const result = renderReproducibilityScore(computeReproducibilityScore('abc', 'abc', [{ sha256: 'x' }], [{ sha256: 'x' }]))
      expect(result.some(l => l.includes('100/100'))).toBe(true)
    })
  })
})
