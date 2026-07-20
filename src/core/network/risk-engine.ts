'use strict';

import { Behavior, BehaviorType, RiskAssessment, RiskFactor } from './types';

const BEHAVIOR_WEIGHTS: Record<BehaviorType, number> = {
  repo_indexed: 25,
  git_history_read: 35,
  git_objects_read: 40,
  git_bundle_created: 60,
  git_bundle_uploaded: 90,
  git_archive_created: 50,
  secrets_scanned: 30,
  secrets_exfiltrated: 95,
  embeddings_generated: 20,
  full_repo_snapshot: 85,
  canary_exfiltrated: 99,
  mass_file_read: 15,
  suspicious_connection: 30,
  ai_prompt_sent: 10,
  code_upload: 50,
  prompt_injection_attempt: 70,
  process_suspicious: 20,
  dns_suspicious: 25,
  tls_suspicious: 25,
  anti_evasion_detected: 60,
  preparation_detected: 40,
  process_chain_detected: 50,
  monitor_awareness_detected: 70,
  monitor_disabled: 80,
  canary_read: 70,
  canary_modified: 75,
  fake_secret_read: 80,
  fake_secret_exfiltrated: 95,
  contaminated_git_read: 75,
  evidence_chain_detected: 65,
  pre_operational_snapshot_detected: 60,
};

const MULTIPLIERS: Record<string, number> = {
  same_host: 1.2,
  multiple_behaviors: 1.3,
  high_confidence: 1.2,
  bundle_plus_upload: 2.0,
  secret_plus_exfil: 2.5,
  anti_evasion_plus_exfil: 2.5,
  canary_triggered: 3.0,
};

const SEQUENCE_MULTIPLIERS: Record<string, { pattern: BehaviorType[]; multiplier: number; label: string }[]> = {
  exfiltration_chain: [
    { pattern: ['preparation_detected'], multiplier: 1.3, label: 'Preparation detected: 1.3x' },
    { pattern: ['git_history_read', 'git_objects_read', 'mass_file_read'], multiplier: 1.4, label: 'Repo content accessed: 1.4x' },
    { pattern: ['git_bundle_created', 'git_archive_created'], multiplier: 1.8, label: 'Repo packaged: 1.8x' },
    { pattern: ['dns_suspicious', 'tls_suspicious'], multiplier: 1.2, label: 'Suspicious channel: 1.2x' },
    { pattern: ['code_upload', 'git_bundle_uploaded', 'secrets_exfiltrated', 'canary_exfiltrated'], multiplier: 2.0, label: 'Exfiltration confirmed: 2.0x' },
  ],
};

const TEMPORAL_WINDOWS_MS = {
  preparation_to_collection: 30_000,
  collection_to_packaging: 30_000,
  packaging_to_exfil: 15_000,
};

export interface RiskContext {
  behaviors: Behavior[];
  stageScores: Record<string, number>;
  temporalMultiplier: number;
  confidence: number;
}

export function assessRisk(behaviors: Behavior[]): RiskAssessment {
  if (behaviors.length === 0) {
    return {
      score: 0,
      level: 'LOW',
      factors: [],
      behaviors: [],
      timestamp: new Date(),
    };
  }

  const factors: RiskFactor[] = [];
  let baseScore = 0;

  const uniqueBehaviors: Map<BehaviorType, Behavior> = new Map();
  for (const b of behaviors) {
    const existing = uniqueBehaviors.get(b.type);
    if (!existing || b.confidence > existing.confidence) {
      uniqueBehaviors.set(b.type, b);
    }
  }

  for (const b of uniqueBehaviors.values()) {
    const weight = BEHAVIOR_WEIGHTS[b.type] || 10;
    const weightedScore = weight * b.confidence;
    baseScore += weightedScore;

    factors.push({
      name: `behavior_${b.type}`,
      contribution: weightedScore,
      detail: `${b.type} (confidence: ${(b.confidence * 100).toFixed(0)}%)`
    });
  }

  const behaviorTypes = new Set(uniqueBehaviors.keys());

  if (behaviorTypes.has('git_bundle_created') && behaviorTypes.has('code_upload')) {
    const bundleUpload = behaviors.filter(
      b => b.type === 'git_bundle_created'
    ).length;
    const uploadCount = behaviors.filter(
      b => b.type === 'code_upload'
    ).length;
    if (bundleUpload > 0 && uploadCount > 0) {
      const mult = MULTIPLIERS.bundle_plus_upload;
      baseScore *= mult;
      factors.push({
        name: 'bundle_plus_upload_multiplier',
        contribution: baseScore - (baseScore / mult),
        detail: `Bundle creation + upload detected: ${mult}x multiplier`
      });
    }
  }

  if (behaviorTypes.has('anti_evasion_detected') &&
      (behaviorTypes.has('code_upload') || behaviorTypes.has('canary_exfiltrated'))) {
    const mult = MULTIPLIERS.anti_evasion_plus_exfil;
    baseScore *= mult;
    factors.push({
      name: 'anti_evasion_plus_exfil_multiplier',
      contribution: baseScore - (baseScore / mult),
      detail: `Anti-evasion + exfiltration detected: ${mult}x multiplier`
    });
  }

  if (behaviorTypes.has('canary_exfiltrated') || behaviorTypes.has('fake_secret_read')) {
    const mult = MULTIPLIERS.canary_triggered;
    baseScore *= mult;
    factors.push({
      name: 'canary_triggered_multiplier',
      contribution: baseScore - (baseScore / mult),
      detail: `Canary trigger detected: ${mult}x multiplier`
    });
  }

  if (behaviorTypes.size >= 3) {
    const mult = MULTIPLIERS.multiple_behaviors;
    baseScore *= mult;
    factors.push({
      name: 'multiple_behaviors_multiplier',
      contribution: baseScore - (baseScore / mult),
      detail: `${behaviorTypes.size} distinct behavior types: ${mult}x multiplier`
    });
  }

  // Secuence-based multipliers: if behaviors form an exfiltration chain, multiply
  let seqMultiplier = 1.0;
  const seqLabel: string[] = [];
  for (const group of SEQUENCE_MULTIPLIERS.exfiltration_chain) {
    const hasAll = group.pattern.every(p => behaviorTypes.has(p));
    if (hasAll) {
      seqMultiplier *= group.multiplier;
      seqLabel.push(group.label);
    }
  }
  if (seqMultiplier > 1.0) {
    baseScore *= seqMultiplier;
    factors.push({
      name: 'sequence_multiplier',
      contribution: baseScore - (baseScore / seqMultiplier),
      detail: `Exfiltration chain sequence: ${seqLabel.join(' → ')} (${seqMultiplier.toFixed(2)}x total)`,
    });
  }

  // Temporal window multiplier: if behaviors happened close together, increase score
  let temporalMultiplier = 1.0;
  if (behaviors.length >= 2) {
    const sortedBehaviors = [...behaviors].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    );
    const gaps: number[] = [];
    for (let i = 1; i < sortedBehaviors.length; i++) {
      gaps.push(
        new Date(sortedBehaviors[i].timestamp).getTime() -
        new Date(sortedBehaviors[i - 1].timestamp).getTime(),
      );
    }
    const avgGap = gaps.reduce((s, g) => s + g, 0) / gaps.length;
    if (avgGap < 30_000) temporalMultiplier = 1.5;
    else if (avgGap < 120_000) temporalMultiplier = 1.3;
    else if (avgGap < 600_000) temporalMultiplier = 1.1;
    baseScore *= temporalMultiplier;
    factors.push({
      name: 'temporal_multiplier',
      contribution: baseScore - (baseScore / temporalMultiplier),
      detail: `Avg ${(avgGap / 1000).toFixed(0)}s between behaviors: ${temporalMultiplier.toFixed(1)}x`,
    });
  }

  const maxPossibleScore = 120;
  const normalizedScore = Math.min(
    Math.round((baseScore / maxPossibleScore) * 100),
    100,
  );

  let level: RiskAssessment['level'];
  if (normalizedScore >= 80) level = 'CRITICAL';
  else if (normalizedScore >= 50) level = 'HIGH';
  else if (normalizedScore >= 20) level = 'MEDIUM';
  else level = 'LOW';

  return {
    score: normalizedScore,
    level,
    factors,
    behaviors,
    timestamp: new Date(),
  };
}

export function computeRiskConfidence(behaviors: Behavior[]): number {
  if (behaviors.length === 0) return 0;
  const avgConfidence = behaviors.reduce((s, b) => s + b.confidence, 0) / behaviors.length;
  const behaviorCountBonus = Math.min(behaviors.length / 5, 1) * 0.15;
  const diversityBonus = Math.min(new Set(behaviors.map(b => b.type)).size / 3, 1) * 0.1;
  return Math.min(avgConfidence * 0.75 + behaviorCountBonus + diversityBonus + 0.1, 0.99);
}

export function assessFlowRisk(
  bytesSent: number, bytesReceived: number, hostname?: string
): RiskFactor[] {
  const factors: RiskFactor[] = [];

  if (bytesSent > 10485760) {
    factors.push({
      name: 'large_upload',
      contribution: 30,
      detail: `Large upload: ${(bytesSent / 1048576).toFixed(1)} MB`
    });
  } else if (bytesSent > 1048576) {
    factors.push({
      name: 'medium_upload',
      contribution: 15,
      detail: `Medium upload: ${(bytesSent / 1048576).toFixed(1)} MB`
    });
  }

  const totalBytes = bytesSent + bytesReceived;
  if (totalBytes > 104857600) {
    factors.push({
      name: 'high_volume_session',
      contribution: 20,
      detail: `High volume session: ${(totalBytes / 1048576).toFixed(1)} MB`
    });
  }

  if (hostname) {
    if (hostname.includes('storage.') || hostname.includes('bucket')) {
      factors.push({
        name: 'storage_host',
        contribution: 15,
        detail: `Connection to storage host: ${hostname}`
      });
    }
  }

  return factors;
}
