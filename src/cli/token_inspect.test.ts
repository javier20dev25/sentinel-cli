import { describe, it, expect } from 'vitest';
import { inspectToken, formatInspectResult } from './token_inspect';

describe('Token Inspector — GitHub tokens', () => {
  it('classifies ghg_ as generic secret (no such GitHub prefix)', async () => {
    const r = await inspectToken('ghg_abc123def456ghi789jkl012mno345pqr');
    expect(r.tokenType).toBe('Generic Secret / API Key');
    expect(r.riskLevel).toBe('medium');
  });

  it('classifies ghp_ as GitHub Classic PAT', async () => {
    const r = await inspectToken('ghp_' + 'a'.repeat(36));
    expect(r.tokenType).toBe('GitHub Classic PAT');
    expect(r.riskLevel).toBe('high');
    expect(r.provider).toBe('GitHub');
  });

  it('classifies github_pat_ as Fine-grained PAT', async () => {
    const r = await inspectToken('github_pat_' + 'a'.repeat(22));
    expect(r.tokenType).toBe('GitHub Fine-grained PAT');
    expect(r.riskLevel).toBe('medium');
  });

  it('classifies ghs_ as GitHub App Installation token', async () => {
    const r = await inspectToken('ghs_' + 'b'.repeat(36));
    expect(r.tokenType).toBe('GitHub App Installation Token');
    expect(r.riskLevel).toBe('low');
  });

  it('classifies ghu_ as User-to-Server token', async () => {
    const r = await inspectToken('ghu_' + 'c'.repeat(36));
    expect(r.tokenType).toBe('GitHub User-to-Server Token');
    expect(r.riskLevel).toBe('medium');
  });

  it('classifies gho_ as OAuth Access token', async () => {
    const r = await inspectToken('gho_' + 'd'.repeat(36));
    expect(r.tokenType).toBe('GitHub OAuth Access Token');
    expect(r.riskLevel).toBe('high');
  });
});

describe('Token Inspector — AWS tokens', () => {
  it('classifies AKIA... as AWS Access Key ID', async () => {
    const r = await inspectToken('AKIA' + 'A'.repeat(16));
    expect(r.tokenType).toBe('AWS Access Key ID');
    expect(r.riskLevel).toBe('critical');
  });
});

describe('Token Inspector — Stripe tokens', () => {
  it('classifies sk_live_ as Stripe Live Secret', async () => {
    const r = await inspectToken('sk_live_' + 'a'.repeat(24));
    expect(r.tokenType).toBe('Stripe Live Secret Key');
    expect(r.riskLevel).toBe('critical');
  });

  it('classifies pk_live_ as Stripe Live Publishable', async () => {
    const r = await inspectToken('pk_live_' + 'b'.repeat(24));
    expect(r.tokenType).toBe('Stripe Live Publishable Key');
    expect(r.riskLevel).toBe('low');
  });
});

describe('Token Inspector — Slack tokens', () => {
  it('classifies xoxb- as Slack Bot token', async () => {
    const r = await inspectToken('xoxb-' + 'a'.repeat(10));
    expect(r.tokenType).toBe('Slack Bot Token');
    expect(r.riskLevel).toBe('high');
  });

  it('classifies xoxa- as Slack App token', async () => {
    const r = await inspectToken('xoxa-' + 'b'.repeat(10));
    expect(r.tokenType).toBe('Slack App Token');
    expect(r.riskLevel).toBe('high');
  });

  it('classifies xoxp- as Slack User token', async () => {
    const r = await inspectToken('xoxp-' + 'c'.repeat(10));
    expect(r.tokenType).toBe('Slack User Token');
    expect(r.riskLevel).toBe('critical');
  });
});

describe('Token Inspector — SendGrid tokens', () => {
  it('classifies SG. as SendGrid API Key', async () => {
    const r = await inspectToken('SG.' + 'a'.repeat(40));
    expect(r.tokenType).toBe('SendGrid API Key');
    expect(r.riskLevel).toBe('critical');
  });
});

describe('Token Inspector — JWT detection', () => {
  it('detects JWT format', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '123', exp: 9999999999 })).toString('base64url');
    const jwt = `${header}.${payload}.signature`;
    const r = await inspectToken(jwt);
    expect(r.tokenType).toBe('JWT (JSON Web Token)');
    expect(r.confidence).toBe('medium');
  });
});

describe('Token Inspector — unknown / generic', () => {
  it('returns unknown for random string', async () => {
    const r = await inspectToken('hello-world');
    expect(r.tokenType).toBe('Unknown');
    expect(r.riskLevel).toBe('low');
  });

  it('detects generic secret for long random string', async () => {
    const r = await inspectToken('a'.repeat(20));
    expect(r.tokenType).toBe('Generic Secret / API Key');
    expect(r.riskLevel).toBe('medium');
  });
});

describe('Token Inspector — formatInspectResult', () => {
  it('returns formatted output with risk badge and recommendations', async () => {
    const r = await inspectToken('ghp_' + 'a'.repeat(36));
    const output = formatInspectResult(r);
    expect(output).toContain('[HIGH]');
    expect(output).toContain('GitHub Classic PAT');
    expect(output).toContain('Recommendations');
  });

  it('shows scopes and expiration when details present', () => {
    const r = {
      tokenType: 'GitHub Fine-grained PAT',
      provider: 'GitHub',
      riskScore: 30,
      riskLevel: 'medium' as const,
      confidence: 'high' as const,
      summary: 'test',
      details: { scopes: ['repo', 'workflow'], expiration: '2026-12-31' },
      recommendations: ['Rotate regularly.'],
    };
    const output = formatInspectResult(r);
    expect(output).toContain('repo, workflow');
    expect(output).toContain('2026-12-31');
  });
});

describe('Token Inspector — edge cases', () => {
  it('trims whitespace from token', async () => {
    const r = await inspectToken('  ghp_' + 'a'.repeat(36) + '  ');
    expect(r.tokenType).toBe('GitHub Classic PAT');
  });

  it('rejects empty tokens gracefully', async () => {
    const r = await inspectToken('');
    expect(r.tokenType).toBe('Unknown');
    expect(r.riskLevel).toBe('low');
  });
});
