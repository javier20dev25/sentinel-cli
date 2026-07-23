// ── Red Team Attack Types ────────────────────────────────────
// Reproducible attack scenarios for resilience testing

export type AttackSeverity = 'critical' | 'high' | 'medium' | 'low'
export type AttackOutcome = 'detected' | 'missed' | 'partial' | 'not_applicable'
export type CampaignStatus = 'pending' | 'running' | 'completed' | 'failed'

// ── Individual Attack Scenario ────────────────────────────────
export interface RedTeamAttack {
  id: string
  name: string
  description: string
  mitreId?: string               // MITRE ATT&CK technique ID
  campaign: string               // Campaign this belongs to
  severity: AttackSeverity
  platform: 'windows' | 'linux' | 'macos' | 'all'

  // What the attack does
  setup: string[]                // Steps to set up the attack
  execution: string[]            // Steps to execute
  cleanup: string[]              // Steps to clean up

  // What Sentinel should detect
  expectedIndicators: string[]   // e.g. ['LoadLibrary', 'CreateRemoteThread']
  expectedEvidenceTypes: string[] // EvidenceType values we expect to see

  // Detection result (filled after run)
  actualOutcome?: AttackOutcome
  detectedIndicators?: string[]
  missedIndicators?: string[]
  detectionLatencyMs?: number
  notes?: string
}

// ── Campaign (group of related attacks) ───────────────────────
export interface RedTeamCampaign {
  id: string
  name: string
  description: string
  objective: string              // What we're testing
  attacks: RedTeamAttack[]
  status: CampaignStatus
  startedAt?: number
  completedAt?: number
  detectionRate?: number         // 0-1
  falseNegativeRate?: number     // 0-1
}

// ── Red Team Report ───────────────────────────────────────────
export interface RedTeamReport {
  timestamp: string
  totalAttacks: number
  detected: number
  missed: number
  partial: number
  notApplicable: number
  detectionRate: number
  campaigns: RedTeamCampaign[]
  weakPoints: WeakPoint[]
  recommendations: string[]
}

export interface WeakPoint {
  attackId: string
  attackName: string
  campaign: string
  severity: AttackSeverity
  reason: string
  recommendation: string
}

// ── Coverage Matrix ───────────────────────────────────────────
export interface CoverageMatrix {
  totalTechniques: number
  coveredTechniques: number
  coverageRate: number
  byCampaign: Record<string, { total: number; covered: number; rate: number }>
  gaps: TechniqueGap[]
}

export interface TechniqueGap {
  technique: string
  campaign: string
  impact: AttackSeverity
  recommendation: string
}
