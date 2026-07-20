import { describe, it, expect, vi, beforeEach } from 'vitest';
import { detectCiEnv, postPrComment } from './ci_comment';

const originalEnv = process.env;

beforeEach(() => {
  vi.restoreAllMocks();
  process.env = { ...originalEnv };
});

describe('detectCiEnv', () => {
  it('returns false when no CI env vars', () => {
    delete process.env.GITHUB_REPOSITORY;
    delete process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_PR_NUMBER;
    delete process.env.GITHUB_REF;
    const result = detectCiEnv();
    expect(result.isCi).toBe(false);
  });

  it('returns true with GITHUB_REPOSITORY set', () => {
    process.env.GITHUB_REPOSITORY = 'owner/repo';
    process.env.GITHUB_TOKEN = 'ghs_fake';
    process.env.GITHUB_PR_NUMBER = '42';
    const result = detectCiEnv();
    expect(result.isCi).toBe(true);
    expect(result.repo).toBe('owner/repo');
    expect(result.prNumber).toBe(42);
    expect(result.token).toBe('ghs_fake');
  });

  it('parses PR number from GITHUB_REF when GITHUB_PR_NUMBER absent', () => {
    process.env.GITHUB_REPOSITORY = 'owner/repo';
    process.env.GITHUB_TOKEN = 'ghs_fake';
    delete process.env.GITHUB_PR_NUMBER;
    process.env.GITHUB_REF = 'refs/pull/123/merge';
    const result = detectCiEnv();
    expect(result.isCi).toBe(true);
    expect(result.prNumber).toBe(123);
  });
});

describe('postPrComment', () => {
  it('handles network error gracefully', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network failure'));
    const result = await postPrComment({
      repo: 'owner/repo',
      prNumber: 1,
      token: 'fake',
      findingsCount: 0,
      agencyScore: 0,
      verdict: 'PASS',
      markdownReport: '# Report',
    });
    expect(result.posted).toBe(false);
    expect(result.error).toContain('Network failure');
  });
});
