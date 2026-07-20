import { BehaviorType, MitreAttackMapping, MitreTactic, BehaviorTimelineStage } from './types';

const MITRE_MAP: Record<BehaviorType, { id: string; name: string; tactic: MitreTactic }> = {
  repo_indexed: { id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' },
  git_history_read: { id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' },
  git_objects_read: { id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' },
  git_bundle_created: { id: 'T1074', name: 'Data Staged', tactic: 'Collection' },
  git_bundle_uploaded: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  git_archive_created: { id: 'T1560', name: 'Archive Collected Data', tactic: 'Collection' },
  secrets_scanned: { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'Credential Access' },
  secrets_exfiltrated: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  embeddings_generated: { id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' },
  full_repo_snapshot: { id: 'T1074', name: 'Data Staged', tactic: 'Collection' },
  canary_exfiltrated: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  mass_file_read: { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
  suspicious_connection: { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
  ai_prompt_sent: { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
  code_upload: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  prompt_injection_attempt: { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration' },
  process_suspicious: { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  dns_suspicious: { id: 'T1572', name: 'Protocol Tunneling', tactic: 'Command and Control' },
  tls_suspicious: { id: 'T1572', name: 'Protocol Tunneling', tactic: 'Command and Control' },
  anti_evasion_detected: { id: 'T1564', name: 'Hide Artifacts', tactic: 'Defense Evasion' },
  preparation_detected: { id: 'T1590', name: 'Gather Victim Network Information', tactic: 'Reconnaissance' },
  process_chain_detected: { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  monitor_awareness_detected: { id: 'T1497', name: 'Virtualization/Sandbox Evasion', tactic: 'Defense Evasion' },
  monitor_disabled: { id: 'T1562', name: 'Impair Defenses', tactic: 'Defense Evasion' },
  canary_read: { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
  canary_modified: { id: 'T1565', name: 'Data Manipulation', tactic: 'Impact' },
  fake_secret_read: { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'Credential Access' },
  fake_secret_exfiltrated: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  contaminated_git_read: { id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' },
  evidence_chain_detected: { id: 'T1074', name: 'Data Staged', tactic: 'Collection' },
  pre_operational_snapshot_detected: { id: 'T1590', name: 'Gather Victim Network Information', tactic: 'Reconnaissance' },
};

const STAGE_MAP: Record<BehaviorType, 'Preparation' | 'Collection' | 'Packaging' | 'Exfiltration' | 'Other'> = {
  repo_indexed: 'Collection',
  git_history_read: 'Collection',
  git_objects_read: 'Collection',
  git_bundle_created: 'Packaging',
  git_bundle_uploaded: 'Exfiltration',
  git_archive_created: 'Packaging',
  secrets_scanned: 'Collection',
  secrets_exfiltrated: 'Exfiltration',
  embeddings_generated: 'Collection',
  full_repo_snapshot: 'Collection',
  canary_exfiltrated: 'Exfiltration',
  mass_file_read: 'Collection',
  suspicious_connection: 'Other',
  ai_prompt_sent: 'Other',
  code_upload: 'Exfiltration',
  prompt_injection_attempt: 'Exfiltration',
  process_suspicious: 'Other',
  dns_suspicious: 'Other',
  tls_suspicious: 'Other',
  anti_evasion_detected: 'Other',
  preparation_detected: 'Preparation',
  process_chain_detected: 'Other',
  monitor_awareness_detected: 'Other',
  monitor_disabled: 'Other',
  canary_read: 'Collection',
  canary_modified: 'Other',
  fake_secret_read: 'Collection',
  fake_secret_exfiltrated: 'Exfiltration',
  contaminated_git_read: 'Collection',
  evidence_chain_detected: 'Collection',
  pre_operational_snapshot_detected: 'Preparation',
};

export function getMitreMapping(type: BehaviorType): MitreAttackMapping {
  const entry = MITRE_MAP[type];
  if (!entry) {
    return { behaviorType: type, techniqueId: 'T1078', techniqueName: 'Valid Accounts', tactic: 'Defense Evasion' };
  }
  return { behaviorType: type, techniqueId: entry.id, techniqueName: entry.name, tactic: entry.tactic };
}

export function getBehaviorStage(type: BehaviorType): 'Preparation' | 'Collection' | 'Packaging' | 'Exfiltration' | 'Other' {
  return STAGE_MAP[type] || 'Other';
}

export function buildMitreMappings(behaviorTypes: BehaviorType[]): MitreAttackMapping[] {
  const seen = new Set<string>();
  return behaviorTypes.map(type => {
    const mapping = getMitreMapping(type);
    const key = `${mapping.techniqueId}:${mapping.tactic}`;
    if (seen.has(key)) return null;
    seen.add(key);
    return mapping;
  }).filter((m): m is MitreAttackMapping => m !== null);
}

export function buildBehaviorTimeline(behaviors: { type: BehaviorType; timestamp: Date; evidence: string[] }[]): BehaviorTimelineStage[] {
  const stages = new Map<string, { behaviors: BehaviorType[]; timestamps: Date[]; evidence: Set<string> }>();

  for (const b of behaviors) {
    const stage = getBehaviorStage(b.type);
    if (!stages.has(stage)) {
      stages.set(stage, { behaviors: [], timestamps: [], evidence: new Set() });
    }
    const entry = stages.get(stage)!;
    entry.behaviors.push(b.type);
    entry.timestamps.push(b.timestamp);
    b.evidence.forEach(e => entry.evidence.add(e));
  }

  const stageOrder: (typeof STAGE_MAP[keyof typeof STAGE_MAP])[] = ['Preparation', 'Collection', 'Packaging', 'Exfiltration', 'Other'];
  return stageOrder
    .filter(stage => stages.has(stage))
    .map(stage => {
      const entry = stages.get(stage)!;
      const sortedTimestamps = [...entry.timestamps].sort((a, b) => a.getTime() - b.getTime());
      return {
        stage,
        behaviors: entry.behaviors,
        timestamp: sortedTimestamps[0],
        evidence: [...entry.evidence].slice(0, 3),
      };
    });
}
