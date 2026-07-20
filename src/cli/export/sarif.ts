import { LiteFinding } from '../../core/lite/lite_scanner';
import { AgencyScoreResult, AgencyDriver } from '../../core/agency_score';
import { EvidenceCard } from '../../core/evidence_card';

const SEVERITY_MAP: Record<string, string> = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'note',
};

function escapeUri(s: string): string {
  return s.replace(/\\/g, '/');
}

export function renderSarif(
  findings: LiteFinding[],
  agency: AgencyScoreResult,
  cards: EvidenceCard[],
): string {
  const rules = new Map<string, {
    id: string;
    shortDescription: string;
    fullDescription: string;
    defaultLevel: string;
    properties: { category: string; riskScore: number };
  }>();

  const results: unknown[] = [];

  for (const f of findings) {
    if (!f.riskScore || f.riskScore === 0) continue;
    const subcode = f.subcode || 'SAST-000';
    if (!rules.has(subcode)) {
      rules.set(subcode, {
        id: subcode,
        shortDescription: f.title || subcode,
        fullDescription: f.description || '',
        defaultLevel: SEVERITY_MAP[f.severity] || 'warning',
        properties: { category: f.category || 'generic', riskScore: f.riskScore },
      });
    }

    const artifactUri = escapeUri(f.file);
    const line = f.line || 1;

    results.push({
      ruleId: subcode,
      level: SEVERITY_MAP[f.severity] || 'warning',
      message: {
        text: f.description || f.title || subcode,
      },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: artifactUri },
          region: {
            startLine: line,
            snippet: f.snippet ? { text: f.snippet } : undefined,
          },
        },
      }],
      properties: {
        riskScore: f.riskScore,
        confidence: f.confidence || 'high',
        evidence: f.evidence,
        category: f.category,
      },
    });
  }

  const tool = {
    driver: {
      name: 'Sentinel',
      version: '4.0.0',
      informationUri: 'https://github.com/anomalyco/sentinel-cli',
      rules: Array.from(rules.values()).map(r => ({
        id: r.id,
        shortDescription: { text: r.shortDescription },
        fullDescription: { text: r.fullDescription },
        defaultConfiguration: { level: r.defaultLevel },
        properties: r.properties,
      })),
    },
  };

  const driverMap = new Map<string, AgencyDriver>();
  for (const d of agency.drivers) {
    driverMap.set(d.subcode, d);
  }

  const sarif: unknown = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool,
      results,
      properties: {
        agencyScore: agency.agencyScore,
        verdict: agency.verdict,
        blastRadius: agency.blastRadius,
        totalFindings: agency.totalFindings,
        criticalCount: agency.criticalCount,
        highCount: agency.highCount,
        drivers: agency.drivers.map(d => ({
          subcode: d.subcode,
          title: d.title,
          category: d.category,
          riskScore: d.riskScore,
          contribution: d.contribution,
        })),
        evidenceCards: cards.map(c => ({
          subcode: c.subcode,
          title: c.title,
          severity: c.severity,
          file: c.file,
          line: c.line,
          riskScore: c.riskScore,
          contribution: c.contribution,
          recommendation: c.recommendation,
        })),
      },
    }],
  };

  return JSON.stringify(sarif, null, 2);
}
