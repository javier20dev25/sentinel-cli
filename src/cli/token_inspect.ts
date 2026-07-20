import { classifyToken, ClassifiedToken } from '../core/token_classifier';

export interface TokenInspectResult {
  tokenType: string;
  provider: string;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'high' | 'medium' | 'low';
  summary: string;
  details?: {
    scopes?: string[];
    expiration?: string;
    lastUsed?: string;
  };
  recommendations: string[];
}

const DETAILED_RECOMMENDATIONS: Record<string, { summary: string; recommendations: string[] }> = {
  'GitHub Fine-grained PAT': {
    summary: 'GitHub fine-grained Personal Access Token — scoped to specific repos/permissions.',
    recommendations: ['Review assigned repository permissions and expiration.', 'Rotate regularly — fine-grained PATs do not auto-expire.'],
  },
  'GitHub Classic PAT': {
    summary: 'GitHub classic Personal Access Token — broad scope access by default.',
    recommendations: ['Replace with fine-grained PAT for repo-level scoping.', 'Check assigned scopes (repo, workflow, admin:org are high risk).', 'Rotate immediately if exposed in code or commits.'],
  },
  'GitHub OAuth Access Token': {
    summary: 'GitHub OAuth access token — issued to OAuth apps, may have broad user scopes.',
    recommendations: ['Verify which OAuth app issued this token.', 'Review scopes granted to the application.', 'Revoke from GitHub Settings → Applications if untrusted.'],
  },
  'GitHub App Installation Token': {
    summary: 'GitHub App installation token — short-lived (1 hour), auto-refreshes.',
    recommendations: ['No immediate action needed — installation tokens expire automatically.', 'If leaked, the token will be useless within 1 hour.'],
  },
  'GitHub User-to-Server Token': {
    summary: 'GitHub user-to-server token — used by GitHub Apps acting on behalf of a user.',
    recommendations: ['Review which GitHub App issued this token.', 'Check expiration — these tokens are typically short-lived.'],
  },
  'AWS Access Key ID': {
    summary: 'AWS Access Key ID — paired with a Secret Access Key for programmatic AWS access.',
    recommendations: ['Rotate immediately if exposed outside AWS environment.', 'Check IAM permissions attached to this key pair.', 'Enable MFA delete on S3 if applicable.'],
  },
  'Stripe Live Secret Key': {
    summary: 'Stripe live secret key — full API access to Stripe account in production.',
    recommendations: ['Rotate immediately from Stripe Dashboard.', 'Never use live keys in client-side code or repositories.', 'Verify no charges or refunds were made by unauthorized parties.'],
  },
  'Stripe Live Publishable Key': {
    summary: 'Stripe live publishable key — intended for client-side use, identifies account.',
    recommendations: ['Publishable keys are public by design, but restrict to known domains in Dashboard.', 'Use test keys (sk_test_/pk_test_) in development environments.'],
  },
  'Slack Bot Token': {
    summary: 'Slack bot token — authenticates a bot user with specific permissions.',
    recommendations: ['Rotate immediately if exposed.', 'Review bot token scopes — use minimum required permissions.'],
  },
  'Slack App Token': {
    summary: 'Slack app-level token — used for Websocket connections and app config.',
    recommendations: ['Rotate immediately if exposed.', 'App tokens can often read channel history — verify scope.'],
  },
  'Slack User Token': {
    summary: 'Slack user token — authenticates as a specific user with their permissions.',
    recommendations: ['Rotate immediately — user tokens grant access to private channels and DMs.', 'Notify the affected user to review their Slack authorized apps.'],
  },
  'SendGrid API Key': {
    summary: 'SendGrid API key — full access to send and manage email via SendGrid.',
    recommendations: ['Rotate immediately from SendGrid dashboard.', 'Check email activity logs for unauthorized usage.'],
  },
  'JWT (JSON Web Token)': {
    summary: 'JSON Web Token — contains base64-encoded claims. Risk depends on signing key and claims.',
    recommendations: ['Decode the payload to inspect claims (exp, iss, sub, scopes).', 'JWTs can be verified offline if the public key is available.', 'If leaked, the token is valid until expiration regardless of revocation status.'],
  },
  'Generic Secret / API Key': {
    summary: 'Generic secret string — matches length/character patterns of common API keys.',
    recommendations: ['Manually verify this is a secret before taking action.', 'Check git history — if this was committed, rotate the key.'],
  },
};

function classifiedToResult(classified: ClassifiedToken): TokenInspectResult {
  const info = DETAILED_RECOMMENDATIONS[classified.tokenType] || {
    summary: 'Token format not recognized — could be a custom secret or non-secret string.',
    recommendations: ['No action needed — this does not match any known token pattern.'],
  };
  return {
    tokenType: classified.tokenType,
    provider: classified.provider,
    riskScore: classified.riskScore,
    riskLevel: classified.riskLevel,
    confidence: classified.confidence,
    summary: info.summary,
    recommendations: info.recommendations,
  };
}

export async function inspectToken(token: string, options?: { check?: boolean }): Promise<TokenInspectResult> {
  const trimmed = token.trim();
  const classified = classifyToken(trimmed);
  const result = classifiedToResult(classified);

  if (options?.check && trimmed.startsWith('gh')) {
    result.details = await checkGitHubToken(trimmed);
  }

  return result;
}

async function checkGitHubToken(token: string): Promise<{ scopes?: string[]; expiration?: string }> {
  try {
    const res = await fetch('https://api.github.com/', {
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'sentinel-cli/4.0' },
    });
    const scopesHeader = res.headers.get('x-oauth-scopes');
    const scopes = scopesHeader ? scopesHeader.split(',').map(s => s.trim()).filter(Boolean) : undefined;

    let expiration: string | undefined;
    const ghPatExpiry = res.headers.get('github-authentication-token-expiration');
    if (ghPatExpiry) {
      expiration = ghPatExpiry;
    }

    return { scopes, expiration };
  } catch {
    return {};
  }
}

export function formatInspectResult(result: TokenInspectResult): string {
  const lines: string[] = [];
  const badge = (severity: string) => {
    switch (severity) {
      case 'critical': return '[CRITICAL]';
      case 'high': return '[HIGH]    ';
      case 'medium': return '[MEDIUM]  ';
      default: return '[LOW]     ';
    }
  };

  lines.push('');
  lines.push(`  ${badge(result.riskLevel)} ${result.tokenType}`);
  lines.push(`  ${'       '.repeat(1)} Provider: ${result.provider}  (confidence: ${result.confidence})`);
  lines.push('');
  lines.push(`  ${result.summary}`);
  lines.push('');

  if (result.details?.scopes && result.details.scopes.length > 0) {
    lines.push(`  Scopes: ${result.details.scopes.join(', ')}`);
  }
  if (result.details?.expiration) {
    lines.push(`  Expiration: ${result.details.expiration}`);
  }
  if (result.details?.scopes || result.details?.expiration) {
    lines.push('');
  }

  lines.push('  Recommendations:');
  for (const rec of result.recommendations) {
    lines.push(`    • ${rec}`);
  }
  lines.push('');

  return lines.join('\n');
}
