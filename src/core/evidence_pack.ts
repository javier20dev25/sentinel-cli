import { LiteFinding } from './lite/lite_scanner';
import { AgencyScoreResult } from './agency_score';
import { EvidenceCard } from './evidence_card';
import { AttackScenario } from './attack_scenario';
import { AgencyGraph, GraphNode } from './agency_graph';

export interface EvidenceItem {
  subcode: string;
  title: string;
  file: string;
  line: number;
  severity: string;
  riskScore: number;
  detail: string;
}

export interface EvidencePack {
  id: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  score: number;
  confidence: number;
  narrative: string;
  impact: string;
  evidenceItems: EvidenceItem[];
  remediationSteps: string[];
  affectedAssets: string[];
  chainLength: number;
}

export function buildEvidencePacks(
  scenarios: AttackScenario[],
  graph: AgencyGraph,
  findings: LiteFinding[],
  cards: EvidenceCard[],
  agency: AgencyScoreResult,
): EvidencePack[] {
  if (scenarios.length === 0) return [];

  const edgeLabels = new Map<string, string>();
  for (const edge of graph.edges) {
    const key = `${edge.sourceId}|${edge.targetId}`;
    edgeLabels.set(key, edge.label);
  }

  const recBySubcode = new Map<string, string>();
  for (const card of cards) {
    if (card.recommendation && !recBySubcode.has(card.subcode)) {
      recBySubcode.set(card.subcode, card.recommendation);
    }
  }

  const packs: EvidencePack[] = [];

  for (const scenario of scenarios) {
    const evidenceItems: EvidenceItem[] = scenario.chain.nodes.map((n: GraphNode) => ({
      subcode: n.subcode,
      title: n.title,
      file: n.file,
      line: n.line,
      severity: n.severity,
      riskScore: n.riskScore,
      detail: buildNodeDetail(n, edgeLabels, scenario.chain.nodes),
    }));

    const uniqueFiles = new Set<string>();
    for (const n of scenario.chain.nodes) {
      uniqueFiles.add(n.file);
    }

    const uniqueSubcodes = new Set<string>();
    for (const n of scenario.chain.nodes) {
      uniqueSubcodes.add(n.subcode);
    }

    const remediationSteps: string[] = [];
    for (const subcode of uniqueSubcodes) {
      const rec = recBySubcode.get(subcode);
      if (rec) remediationSteps.push(`${subcode}: ${rec}`);
    }

    const affectedAssets = Array.from(uniqueFiles).sort();

    const narrative = buildNarrative(scenario, evidenceItems, edgeLabels);

    packs.push({
      id: scenario.id,
      title: scenario.name,
      severity: scenario.severity,
      score: scenario.score,
      confidence: scenario.confidence,
      narrative,
      impact: scenario.impact,
      evidenceItems,
      remediationSteps,
      affectedAssets,
      chainLength: scenario.chain.nodes.length,
    });
  }

  packs.sort((a, b) => b.score - a.score);

  return packs;
}

function buildNodeDetail(
  node: GraphNode,
  edgeLabels: Map<string, string>,
  chainNodes: GraphNode[],
): string {
  const idx = chainNodes.indexOf(node);
  if (idx < 0 || idx >= chainNodes.length - 1) return '';

  const next = chainNodes[idx + 1];
  const key = `${node.id}|${next.id}`;
  const label = edgeLabels.get(key);
  return label ? `${node.subcode} → ${next.subcode}: ${label}` : '';
}

function buildNarrative(
  scenario: AttackScenario,
  evidenceItems: EvidenceItem[],
  edgeLabels: Map<string, string>,
): string {
  const parts: string[] = [];

  parts.push(scenario.description);

  if (evidenceItems.length > 0) {
    const steps = evidenceItems
      .filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH')
      .slice(0, 3)
      .map(e => `${e.subcode} in ${e.file}:${e.line}`);
    if (steps.length > 0) {
      parts.push(`Key evidence: ${steps.join(', ')}.`);
    }
  }

  return parts.join(' ');
}
