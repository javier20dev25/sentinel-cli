import { AgencyScoreResult } from '../../core/agency_score';
import { LiteFinding } from '../../core/lite/lite_scanner';

export interface PolicyResult {
  shouldFail: boolean;
  reason: string;
}

export interface PolicyOptions {
  failOnScore?: number;
  failOnCritical?: boolean;
  failOnHigh?: boolean;
  failOnVerdict?: 'BLOCK' | 'REVIEW';
}

const VERDICT_ORDER: Record<string, number> = { PASS: 0, REVIEW: 1, BLOCK: 2 };

export function evaluatePolicy(
  findings: LiteFinding[],
  agency: AgencyScoreResult,
  options: PolicyOptions,
): PolicyResult {
  const failures: string[] = [];

  // fail-on-score
  if (options.failOnScore !== undefined && options.failOnScore >= 0 && options.failOnScore <= 100) {
    if (agency.agencyScore >= options.failOnScore) {
      failures.push(`Agency Score ${agency.agencyScore} >= threshold ${options.failOnScore}`);
    }
  }

  // fail-on-critical
  if (options.failOnCritical) {
    const critical = findings.filter(f => f.severity === 'CRITICAL');
    if (critical.length > 0) {
      const subcodes = [...new Set(critical.map(f => f.subcode).filter(Boolean))].join(', ');
      failures.push(`${critical.length} CRITICAL finding(s) detected: ${subcodes}`);
    }
  }

  // fail-on-high
  if (options.failOnHigh) {
    const high = findings.filter(f => f.severity === 'HIGH');
    if (high.length > 0) {
      const subcodes = [...new Set(high.map(f => f.subcode).filter(Boolean))].join(', ');
      failures.push(`${high.length} HIGH finding(s) detected: ${subcodes}`);
    }
  }

  // fail-on-verdict
  if (options.failOnVerdict) {
    const threshold = VERDICT_ORDER[options.failOnVerdict] ?? 1;
    const actual = VERDICT_ORDER[agency.verdict] ?? 0;
    if (actual >= threshold) {
      failures.push(`Verdict ${agency.verdict} meets or exceeds threshold ${options.failOnVerdict}`);
    }
  }

  if (failures.length > 0) {
    return { shouldFail: true, reason: failures.join('; ') };
  }

  return { shouldFail: false, reason: '' };
}
