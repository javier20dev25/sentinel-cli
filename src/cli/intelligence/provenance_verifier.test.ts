import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('child_process', () => {
  const execSync = vi.fn()
  return { execSync }
})

import { execSync } from 'child_process'
import { ProvenanceVerifier } from './provenance_verifier'

const verifier = new ProvenanceVerifier()

describe('ProvenanceVerifier', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('checkCommandAvailable', () => {
    it('returns false when npm does not support attestations', () => {
      vi.mocked(execSync).mockImplementation(() => {
        throw new Error('Command failed: npm attestation --help')
      })
      expect(verifier.checkCommandAvailable()).toBe(false)
    })

    it('returns true when npm attestation is available', () => {
      vi.mocked(execSync).mockReturnValue('')
      expect(verifier.checkCommandAvailable()).toBe(true)
    })
  })

  describe('verify', () => {
    it('returns verified=false with error when npm command fails', async () => {
      vi.mocked(execSync).mockImplementation(() => {
        const err: any = new Error('npm ERR! command failed')
        err.stderr = 'npm ERR! attestation verify failed'
        err.stdout = ''
        throw err
      })

      const result = await verifier.verify('lodash', '4.17.21')
      expect(result.verified).toBe(false)
      expect(result.attestations).toHaveLength(0)
      expect(result.error).toBe('npm ERR! attestation verify failed')
    })

    it('parses attestation JSON correctly', async () => {
      const mockOutput = JSON.stringify([
        {
          type: 'attestation',
          verificationResult: {
            verified: true,
            results: [
              {
                signer: { issuer: 'https://registry.npmjs.org' },
                timestamp: '2024-01-15T10:30:00.000Z'
              }
            ]
          },
          attestation: {
            version: 1,
            subject: [{ name: 'lodash@4.17.21' }],
            predicateType: 'https://slsa.dev/provenance/v1',
            predicate: {
              buildDefinition: {}
            }
          }
        }
      ])
      vi.mocked(execSync).mockReturnValue(mockOutput)

      const result = await verifier.verify('lodash', '4.17.21')
      expect(result.packageName).toBe('lodash')
      expect(result.version).toBe('4.17.21')
      expect(result.verified).toBe(true)
      expect(result.attestations).toHaveLength(1)
      expect(result.attestations[0].type).toBe('attestation')
      expect(result.attestations[0].issuer).toBe('https://registry.npmjs.org')
      expect(result.attestations[0].subject).toBe('lodash@4.17.21')
      expect(result.attestations[0].predicateType).toBe('https://slsa.dev/provenance/v1')
      expect(result.attestations[0].timestamp).toBe('2024-01-15T10:30:00.000Z')
      expect(result.attestations[0].slsaLevel).toBe('SLSA v1')
      expect(result.error).toBeUndefined()
    })

    it('handles empty attestation response', async () => {
      vi.mocked(execSync).mockReturnValue('[]')

      const result = await verifier.verify('lodash', '4.17.21')
      expect(result.verified).toBe(false)
      expect(result.attestations).toHaveLength(0)
      expect(result.error).toBeUndefined()
    })

    it('handles scoped packages (@scope/name)', async () => {
      const mockOutput = JSON.stringify([
        {
          type: 'attestation',
          verificationResult: {
            verified: true,
            results: [
              {
                signer: { issuer: 'https://registry.npmjs.org' },
                timestamp: '2024-02-01T12:00:00.000Z'
              }
            ]
          },
          attestation: {
            version: 1,
            subject: [{ name: '@scope/my-pkg@2.0.0' }],
            predicateType: 'https://slsa.dev/provenance/v1',
            predicate: {}
          }
        }
      ])
      vi.mocked(execSync).mockReturnValue(mockOutput)

      const result = await verifier.verify('@scope/my-pkg', '2.0.0')
      expect(result.packageName).toBe('@scope/my-pkg')
      expect(result.version).toBe('2.0.0')
      expect(result.verified).toBe(true)
      expect(result.attestations).toHaveLength(1)
      expect(result.attestations[0].subject).toBe('@scope/my-pkg@2.0.0')
    })
  })
})
