import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { OSVIntegrator } from './osv_integrator'

describe('OSVIntegrator queryBatch', () => {
  let integrator: OSVIntegrator
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    integrator = new OSVIntegrator()
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns empty array for empty input', async () => {
    const results = await integrator.queryBatch([])
    expect(results).toEqual([])
  })

  it('returns 1 result for 1 package', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          results: {
            '0': {
              vulns: [
                {
                  id: 'GHSA-xxxx-xxxx-xxxx',
                  summary: 'Test vuln',
                  aliases: ['CVE-2024-1234'],
                  severity: [{ type: 'CVSS_V3', score: '7.5' }],
                  published: '2024-01-01T00:00:00Z',
                  modified: '2024-01-02T00:00:00Z'
                }
              ]
            }
          }
        })
    })

    const results = await integrator.queryBatch([{ name: 'lodash', version: '4.17.21' }])
    expect(results).toHaveLength(1)
    expect(results[0].packageName).toBe('lodash')
    expect(results[0].version).toBe('4.17.21')
    expect(results[0].vulnerabilities).toHaveLength(1)
    expect(results[0].vulnerabilities[0].id).toBe('GHSA-xxxx-xxxx-xxxx')
  })

  it('falls back to individual queries when batch endpoint fails', async () => {
    const batchReject = new Error('Batch endpoint unreachable')

    fetchMock
      .mockRejectedValueOnce(batchReject)
      .mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            vulns: [
              {
                id: 'GHSA-xxxx-xxxx-xxxx',
                summary: 'Fallback vuln',
                aliases: [],
                severity: [],
                published: '',
                modified: ''
              }
            ]
          })
      })

    const results = await integrator.queryBatch([
      { name: 'axios', version: '1.6.0' },
      { name: 'express', version: '4.18.0' }
    ])

    expect(results).toHaveLength(2)
    expect(results[0].packageName).toBe('axios')
    expect(results[0].vulnerabilities[0].id).toBe('GHSA-xxxx-xxxx-xxxx')
    expect(results[1].packageName).toBe('express')
    expect(results[1].vulnerabilities[0].id).toBe('GHSA-xxxx-xxxx-xxxx')

    const batchCalls = fetchMock.mock.calls.filter(
      (c: any[]) => c[0] === 'https://api.osv.dev/v1/querybatch'
    )
    const singleCalls = fetchMock.mock.calls.filter(
      (c: any[]) => c[0] === 'https://api.osv.dev/v1/query'
    )
    expect(batchCalls).toHaveLength(1)
    expect(singleCalls).toHaveLength(2)
  })

  it('maintains correct order matching input packages', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          results: {
            '0': {
              vulns: [
                {
                  id: 'GHSA-0001',
                  summary: '',
                  aliases: [],
                  severity: [],
                  published: '',
                  modified: ''
                }
              ]
            },
            '1': { vulns: [] },
            '2': {
              vulns: [
                {
                  id: 'GHSA-0003',
                  summary: '',
                  aliases: [],
                  severity: [],
                  published: '',
                  modified: ''
                }
              ]
            }
          }
        })
    })

    const results = await integrator.queryBatch([
      { name: 'alpha', version: '1.0.0' },
      { name: 'beta', version: '2.0.0' },
      { name: 'gamma', version: '3.0.0' }
    ])

    expect(results).toHaveLength(3)
    expect(results[0].packageName).toBe('alpha')
    expect(results[0].vulnerabilities).toHaveLength(1)
    expect(results[0].vulnerabilities[0].id).toBe('GHSA-0001')
    expect(results[1].packageName).toBe('beta')
    expect(results[1].vulnerabilities).toHaveLength(0)
    expect(results[2].packageName).toBe('gamma')
    expect(results[2].vulnerabilities).toHaveLength(1)
    expect(results[2].vulnerabilities[0].id).toBe('GHSA-0003')
  })

  it('handles missing result index gracefully', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          results: {
            '1': {
              vulns: [
                {
                  id: 'GHSA-0002',
                  summary: '',
                  aliases: [],
                  severity: [],
                  published: '',
                  modified: ''
                }
              ]
            }
          }
        })
    })

    const results = await integrator.queryBatch([
      { name: 'missing', version: '1.0.0' },
      { name: 'present', version: '2.0.0' }
    ])

    expect(results).toHaveLength(2)
    expect(results[0].packageName).toBe('missing')
    expect(results[0].vulnerabilities).toHaveLength(0)
    expect(results[1].packageName).toBe('present')
    expect(results[1].vulnerabilities).toHaveLength(1)
  })
})
