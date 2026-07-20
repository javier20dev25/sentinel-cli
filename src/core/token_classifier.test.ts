import { describe, it, expect } from 'vitest';
import { classifyToken, calculateRiskScore, extractTokenValue } from './token_classifier';

describe('classifyToken — GitHub tokens', () => {
  it('classifies ghp_ as GitHub Classic PAT', () => {
    const r = classifyToken('ghp_' + 'a'.repeat(36));
    expect(r.tokenType).toBe('GitHub Classic PAT');
    expect(r.riskLevel).toBe('high');
    expect(r.riskScore).toBe(60);
    expect(r.provider).toBe('GitHub');
  });

  it('classifies github_pat_ as Fine-grained PAT', () => {
    const r = classifyToken('github_pat_' + 'a'.repeat(22));
    expect(r.tokenType).toBe('GitHub Fine-grained PAT');
    expect(r.riskLevel).toBe('medium');
    expect(r.riskScore).toBe(30);
  });

  it('classifies ghs_ as GitHub App Installation token', () => {
    const r = classifyToken('ghs_' + 'b'.repeat(36));
    expect(r.tokenType).toBe('GitHub App Installation Token');
    expect(r.riskLevel).toBe('low');
    expect(r.riskScore).toBe(15);
  });

  it('classifies ghu_ as User-to-Server token', () => {
    const r = classifyToken('ghu_' + 'c'.repeat(36));
    expect(r.tokenType).toBe('GitHub User-to-Server Token');
    expect(r.riskLevel).toBe('medium');
    expect(r.riskScore).toBe(35);
  });

  it('classifies gho_ as OAuth Access token', () => {
    const r = classifyToken('gho_' + 'd'.repeat(36));
    expect(r.tokenType).toBe('GitHub OAuth Access Token');
    expect(r.riskLevel).toBe('high');
    expect(r.riskScore).toBe(50);
  });
});

describe('classifyToken — AWS tokens', () => {
  it('classifies AKIA... as AWS Access Key ID', () => {
    const r = classifyToken('AKIA' + 'A'.repeat(16));
    expect(r.tokenType).toBe('AWS Access Key ID');
    expect(r.riskLevel).toBe('critical');
    expect(r.riskScore).toBe(80);
  });
});

describe('classifyToken — Stripe tokens', () => {
  it('classifies sk_live_ as Stripe Live Secret', () => {
    const r = classifyToken('sk_live_' + 'a'.repeat(24));
    expect(r.tokenType).toBe('Stripe Live Secret Key');
    expect(r.riskLevel).toBe('critical');
    expect(r.riskScore).toBe(80);
  });

  it('classifies pk_live_ as Stripe Live Publishable', () => {
    const r = classifyToken('pk_live_' + 'b'.repeat(24));
    expect(r.tokenType).toBe('Stripe Live Publishable Key');
    expect(r.riskLevel).toBe('low');
    expect(r.riskScore).toBe(10);
  });
});

describe('classifyToken — Slack tokens', () => {
  it('classifies xoxb- as Slack Bot token', () => {
    const r = classifyToken('xoxb-' + 'a'.repeat(10));
    expect(r.tokenType).toBe('Slack Bot Token');
    expect(r.riskLevel).toBe('high');
    expect(r.riskScore).toBe(60);
  });

  it('classifies xoxa- as Slack App token', () => {
    const r = classifyToken('xoxa-' + 'b'.repeat(10));
    expect(r.tokenType).toBe('Slack App Token');
    expect(r.riskLevel).toBe('high');
    expect(r.riskScore).toBe(60);
  });

  it('classifies xoxp- as Slack User token', () => {
    const r = classifyToken('xoxp-' + 'c'.repeat(10));
    expect(r.tokenType).toBe('Slack User Token');
    expect(r.riskLevel).toBe('critical');
    expect(r.riskScore).toBe(75);
  });
});

describe('classifyToken — SendGrid tokens', () => {
  it('classifies SG. as SendGrid API Key', () => {
    const r = classifyToken('SG.' + 'a'.repeat(40));
    expect(r.tokenType).toBe('SendGrid API Key');
    expect(r.riskLevel).toBe('critical');
    expect(r.riskScore).toBe(80);
  });
});

describe('classifyToken — JWT detection', () => {
  it('detects JWT format', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '123', exp: 9999999999 })).toString('base64url');
    const jwt = `${header}.${payload}.signature`;
    const r = classifyToken(jwt);
    expect(r.tokenType).toBe('JWT (JSON Web Token)');
    expect(r.confidence).toBe('medium');
    expect(r.riskScore).toBe(45);
  });
});

describe('classifyToken — unknown / generic', () => {
  it('returns unknown for random short string', () => {
    const r = classifyToken('hello-world');
    expect(r.tokenType).toBe('Unknown');
    expect(r.riskLevel).toBe('low');
    expect(r.riskScore).toBe(0);
  });

  it('detects generic secret for long random string', () => {
    const r = classifyToken('a'.repeat(20));
    expect(r.tokenType).toBe('Generic Secret / API Key');
    expect(r.riskLevel).toBe('medium');
    expect(r.riskScore).toBe(40);
  });

  it('trims whitespace', () => {
    const r = classifyToken('  ghp_' + 'a'.repeat(36) + '  ');
    expect(r.tokenType).toBe('GitHub Classic PAT');
    expect(r.riskScore).toBe(60);
  });

  it('returns unknown for empty string', () => {
    const r = classifyToken('');
    expect(r.tokenType).toBe('Unknown');
    expect(r.riskScore).toBe(0);
  });
});

describe('calculateRiskScore', () => {
  it('returns base score when no permissions given', () => {
    expect(calculateRiskScore(60)).toBe(60);
  });

  it('adds permission scores', () => {
    expect(calculateRiskScore(60, ['repo', 'workflow'])).toBe(85);
  });

  it('caps at 100', () => {
    expect(calculateRiskScore(80, ['repo', 'workflow', 'admin:org'])).toBe(100);
  });

  it('floors at 0', () => {
    expect(calculateRiskScore(-10)).toBe(0);
  });

  it('ignores unknown permission keys', () => {
    expect(calculateRiskScore(60, ['nonexistent'])).toBe(60);
  });
});

describe('extractTokenValue', () => {
  it('extracts GitHub PAT from snippet', () => {
    const token = 'ghp_' + 'a'.repeat(36);
    const snippet = `const t = '${token}';`;
    expect(extractTokenValue(snippet, 'SECRET_GITHUB_TOKEN')).toBe(token);
  });

  it('extracts GitHub fine-grained PAT from snippet', () => {
    const token = 'github_pat_' + 'a'.repeat(22);
    const snippet = `const t = '${token}';`;
    expect(extractTokenValue(snippet, 'SECRET_GITHUB_TOKEN')).toBe(token);
  });

  it('extracts AWS key from snippet', () => {
    const token = 'AKIA' + 'A'.repeat(16);
    const snippet = `key=${token}`;
    expect(extractTokenValue(snippet, 'SECRET_AWS_KEY_ID')).toBe(token);
  });

  it('extracts Stripe key from snippet', () => {
    const token = 'sk_live_' + 'a'.repeat(24);
    const snippet = `stripe=${token}`;
    expect(extractTokenValue(snippet, 'SECRET_STRIPE_KEY')).toBe(token);
  });

  it('extracts SendGrid key from snippet', () => {
    const token = 'SG.' + 'a'.repeat(40);
    const snippet = `sg=${token}`;
    expect(extractTokenValue(snippet, 'SECRET_SENDGRID_KEY')).toBe(token);
  });

  it('extracts Slack token from snippet', () => {
    const token = 'xoxb-' + 'a'.repeat(10);
    const snippet = `slack=${token}`;
    expect(extractTokenValue(snippet, 'SECRET_SLACK_TOKEN')).toBe(token);
  });

  it('returns null for unmatched secret type', () => {
    expect(extractTokenValue('anything', 'UNKNOWN_TYPE')).toBeNull();
  });

  it('returns null when no token found in snippet', () => {
    expect(extractTokenValue('just some text', 'SECRET_GITHUB_TOKEN')).toBeNull();
  });
});
