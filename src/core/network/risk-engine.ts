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

  // Deduplicate behaviors by type, keeping the one with the highest confidence
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

  // Normalization: instead of dividing by the sum of the entire behavior universe
  // (which dilutes even critical behaviors to LOW), we use a realistic maximum
  // base score threshold (e.g., 120) where anything at or above this is 100% risk.
  const maxPossibleScore = 120;
  const normalizedScore = Math.min(
    Math.round((baseScore / maxPossibleScore) * 100),
    100
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
