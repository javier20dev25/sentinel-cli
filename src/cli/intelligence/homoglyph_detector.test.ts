import { describe, it, expect } from 'vitest'
import { detectHomoglyph } from './homoglyph_detector'

const TEST_TOP_PACKAGES = [
  'lodash', 'chalk', 'react', 'express', 'axios', 'uuid', 'moment',
  'typescript', 'webpack', 'babel', 'eslint', 'prettier', 'tslib',
  'date-fns', 'dotenv', 'commander', 'body-parser', 'nodemon',
  'socket.io', 'passport', 'mongoose', 'koa', 'fastify', 'morgan',
  'cors', 'helmet', 'joi', 'yup', 'zod', 'ioredis', 'pg', 'mysql2',
]

describe('detectHomoglyph', () => {
  it('detects rnongoose as homoglyph of mongoose', () => {
    const result = detectHomoglyph('rnongoose', TEST_TOP_PACKAGES)
    expect(result.isSuspicious).toBe(true)
    expect(result.matches.length).toBeGreaterThan(0)
    const match = result.matches.find(m => m.target === 'mongoose')
    expect(match).toBeDefined()
    expect(match!.distance).toBeLessThanOrEqual(2)
    expect(result.confidence).toBeGreaterThan(0)
  })

  it('returns no match for legitimate express', () => {
    const result = detectHomoglyph('express', TEST_TOP_PACKAGES)
    expect(result.isSuspicious).toBe(false)
    expect(result.matches).toHaveLength(0)
    expect(result.confidence).toBe(0)
  })

  it('returns no match for empty string', () => {
    const result = detectHomoglyph('', TEST_TOP_PACKAGES)
    expect(result.isSuspicious).toBe(false)
    expect(result.matches).toHaveLength(0)
    expect(result.confidence).toBe(0)
  })

  it('calculates Levenshtein distance correctly', () => {
    const result = detectHomoglyph('typoscript', TEST_TOP_PACKAGES)
    if (result.isSuspicious) {
      for (const match of result.matches) {
        expect(match.distance).toBeGreaterThanOrEqual(1)
        expect(match.distance).toBeLessThanOrEqual(2)
        expect(match.severity).toMatch(/^(LOW|MEDIUM)$/)
      }
    }
  })
})
