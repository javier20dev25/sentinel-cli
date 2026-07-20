import { LiteFinding } from '../../core/lite/lite_scanner';
import { AgencyScoreResult } from '../../core/agency_score';
import { EvidenceCard } from '../../core/evidence_card';

export interface EnrichedJsonOutput {
  host: string;
  scanTimeMs: number;
  memoryMB: number;
  totalFindings: number;
  agencyScore: number;
  verdict: string;
  blastRadius: string;
  drivers: {
    subcode: string;
    title: string;
    category: string;
    riskScore: number;
    contribution: number;
    confidence: string;
  }[];
  cards: {
    subcode: string;
    title: string;
    category: string;
    severity: string;
    riskScore: number;
    confidence: string;
    file: string;
    line: number;
    evidence?: string;
    description: string;
    contribution?: number;
    recommendation?: string;
  }[];
  findings: LiteFinding[];
}

export function renderEnrichedJson(
  findings: LiteFinding[],
  agency: AgencyScoreResult,
  cards: EvidenceCard[],
  meta: { host: string; scanTimeMs: number; memoryMB: number },
): string {
  const output: EnrichedJsonOutput = {
    host: meta.host,
    scanTimeMs: meta.scanTimeMs,
    memoryMB: meta.memoryMB,
    totalFindings: agency.totalFindings,
    agencyScore: agency.agencyScore,
    verdict: agency.verdict,
    blastRadius: agency.blastRadius,
    drivers: agency.drivers,
    cards: cards.map(c => ({
      subcode: c.subcode,
      title: c.title,
      category: c.category,
      severity: c.severity,
      riskScore: c.riskScore,
      confidence: c.confidence,
      file: c.file,
      line: c.line,
      evidence: c.evidence,
      description: c.description,
      contribution: c.contribution,
      recommendation: c.recommendation,
    })),
    findings,
  };
  return JSON.stringify(output, null, 2);
}
